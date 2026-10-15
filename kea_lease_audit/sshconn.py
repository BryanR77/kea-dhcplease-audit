"""SSH transport: remote commands and port-forwards, with optional connection reuse.

With `ssh.control_persist` > 0, the first use of a server starts a background
OpenSSH master connection (ControlMaster) that stays up for that many seconds
after its last use. Later runs - e.g. a monitoring check every few minutes -
reuse it, so the server sees one login instead of one per run, and each run
skips the key exchange. Without it, every command and tunnel is a fresh login.
"""

import contextlib
import fcntl
import hashlib
import os
import socket
import subprocess
import tempfile
import time

# sun_path is 108 bytes on Linux (104 on BSD/macOS), and OpenSSH appends a
# 17-character temporary suffix while creating the socket.
_MAX_CONTROL_PATH = 104 - 17


class SSHError(Exception):
    pass


def _target(server):
    s = server.settings["ssh"]
    return f"{s['user']}@{server.host}" if s.get("user") else server.host


def _options(server):
    s = server.settings["ssh"]
    opts = ["-o", "BatchMode=yes", "-o", f"ConnectTimeout={min(server.settings['timeout'], 15)}",
            "-p", str(s["port"])]
    if s.get("identity_file"):
        # Offer only this key, so keys in a running agent can't use up the
        # server's MaxAuthTries first.
        opts += ["-i", s["identity_file"], "-o", "IdentitiesOnly=yes"]
    if s.get("known_hosts_file"):
        opts += ["-o", f"UserKnownHostsFile={s['known_hosts_file']}"]
    for opt in s.get("options") or []:
        opts += ["-o", opt]
    return opts


def control_dir(settings):
    """Directory for master sockets, or None when connection reuse is off."""
    s = settings["ssh"]
    if not s.get("control_persist"):
        return None
    if s.get("control_dir"):
        return os.path.expanduser(s["control_dir"])
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = runtime if runtime and os.path.isdir(runtime) else os.path.expanduser("~/.ssh")
    return os.path.join(base, "kea-lease-audit")


def _control_path(server):
    d = control_dir(server.settings)
    if d is None:
        return None
    s = server.settings["ssh"]
    # Our own short hash of everything that makes the connection distinct
    # (OpenSSH's %C is 40 chars, which overflows sun_path too easily).
    ident = "\0".join([_target(server), str(s["port"]), s.get("identity_file") or "",
                       *(s.get("options") or [])])
    path = os.path.join(d, hashlib.sha256(ident.encode()).hexdigest()[:16])
    if len(path.encode()) > _MAX_CONTROL_PATH:
        raise SSHError(f"{server.name}: ssh.control_dir {d} is too long for a control socket "
                       f"(keep it under {_MAX_CONTROL_PATH - 17} bytes)")
    return path


def _ensure_master(server, path):
    """Start a persistent master for this server unless one is already up."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    base = ["ssh"] + _options(server) + ["-o", f"ControlPath={path}"]
    # Lock so concurrent runs (e.g. two monitoring checks) don't both start one.
    with open(path + ".lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        check = subprocess.run(base + ["-O", "check", _target(server)], stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check.returncode == 0:
            return
        if os.path.exists(path):
            os.unlink(path)  # stale socket left by a master that died
        persist = int(server.settings["ssh"]["control_persist"])
        # The master runs `true`, then backgrounds itself and lingers. Its stdio
        # must not be our pipes, or we'd wait on it until it exits.
        with tempfile.TemporaryFile("w+") as err:
            try:
                proc = subprocess.run(base + ["-o", "ControlMaster=yes", "-o", f"ControlPersist={persist}",
                                              _target(server), "true"],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
                                      timeout=server.settings["timeout"])
            except subprocess.TimeoutExpired as e:
                raise SSHError(f"{server.name}: ssh login timed out") from e
            if proc.returncode != 0:
                err.seek(0)
                raise SSHError(f"{server.name}: ssh failed ({proc.returncode}): {err.read().strip()}")


def command(server, extra=()):
    """argv for `ssh <server> ...`, routed through the master when reuse is on."""
    path = _control_path(server)
    cmd = ["ssh"] + _options(server)
    if path:
        _ensure_master(server, path)
        # ControlMaster=no: use the master if it's there, else connect directly.
        cmd += ["-o", f"ControlPath={path}", "-o", "ControlMaster=no"]
    return cmd + list(extra) + [_target(server)]


def run(server, remote_cmd, timeout):
    try:
        return subprocess.run(command(server) + [remote_cmd], capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=timeout)
    except subprocess.TimeoutExpired as e:
        raise SSHError(f"{server.name}: ssh timed out") from e


def close(server):
    """Ask the master for this server, if any, to exit."""
    path = _control_path(server)
    if path and os.path.exists(path):
        subprocess.run(["ssh"] + _options(server) + ["-o", f"ControlPath={path}", "-O", "exit",
                                                     _target(server)],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if path:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path + ".lock")


def _free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_listening(server, port, alive=lambda: True):
    deadline = time.time() + server.settings["timeout"]
    while True:
        if not alive():
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
            return True
        except OSError:
            if time.time() > deadline:
                raise SSHError(f"{server.name}: ssh tunnel did not come up within "
                               f"{server.settings['timeout']}s")
            time.sleep(0.1)


@contextlib.contextmanager
def tunnel(server, remote_host, remote_port):
    """Forward a free local port to remote_host:remote_port as seen from the server."""
    lport = _free_port()
    spec = f"127.0.0.1:{lport}:{remote_host}:{remote_port}"
    path = _control_path(server)
    if path:
        base = command(server)  # ensures the master is up
        ctl = base[:-1] + ["-O"]
        target = base[-1:]
        proc = subprocess.run(ctl + ["forward", "-L", spec] + target, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL)
        if proc.returncode != 0:
            raise SSHError(f"{server.name}: ssh port-forward failed: {proc.stderr.strip()}")
        try:
            _wait_listening(server, lport)
            yield ("127.0.0.1", lport)
        finally:
            subprocess.run(ctl + ["cancel", "-L", spec] + target, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return

    proc = subprocess.Popen(command(server, ["-N", "-o", "ExitOnForwardFailure=yes", "-L", spec]),
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE, text=True)
    try:
        if not _wait_listening(server, lport, alive=lambda: proc.poll() is None):
            raise SSHError(f"{server.name}: ssh tunnel failed ({proc.returncode}): "
                           f"{proc.stderr.read().strip()}")
        yield ("127.0.0.1", lport)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        proc.stderr.close()
