"""Fetch the current lease set from a server, via the Kea API or over SSH."""

import base64
import contextlib
import json
import shlex
import ssl
import time
import urllib.error
import urllib.request

from . import lease as lease_mod
from . import memfile, sshconn


class CollectError(Exception):
    pass


class Snapshot:
    """Leases for one server/family, plus the time window the fetch covered."""

    def __init__(self, server, family, leases, started, finished, server_time=None):
        self.server = server
        self.family = family
        self.leases = leases          # {key: Lease}
        self.started = started        # auditor clock, epoch seconds
        self.finished = finished
        self.server_time = server_time  # server clock at fetch, if known

    @property
    def clock_offset(self):
        """Server clock minus auditor clock, in seconds (None if unknown)."""
        if self.server_time is None:
            return None
        return self.server_time - (self.started + self.finished) / 2


def collect(server, family):
    try:
        if server.method == "api":
            with api_endpoint(server) as endpoint:
                return _collect_api_pages(server, family, endpoint)
        return _collect_ssh(server, family)
    except sshconn.SSHError as e:
        raise CollectError(str(e)) from e


# --------------------------------------------------------------------------- API

@contextlib.contextmanager
def api_endpoint(server, tunnel=None):
    """Yield the (host, port) to reach the API at: a tunnel's local end, or None for direct."""
    api = server.settings["api"]
    if tunnel is None:
        tunnel = api.get("tunnel")
    if not tunnel:
        yield None
        return
    try:
        with sshconn.tunnel(server, api["tunnel_host"], api["port"]) as endpoint:
            yield endpoint
    except sshconn.SSHError as e:
        raise CollectError(str(e)) from e


def api_call(server, family, command, arguments=None, endpoint=None):
    """Send one command; returns (response object, HTTP Date header)."""
    api = server.settings["api"]
    host, port = endpoint or (server.host, api["port"])
    url = f"{api['scheme']}://{host}:{port}{api['path']}"
    body = {"command": command}
    service = api.get("service")
    if service is True:
        service = f"dhcp{family}"
    if service:
        body["service"] = [service]
    if arguments is not None:
        body["arguments"] = arguments

    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    password = server.api_password()
    if api.get("username"):
        token = base64.b64encode(f"{api['username']}:{password or ''}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")

    ctx = None
    if api["scheme"] == "https":
        ctx = ssl.create_default_context(cafile=api.get("ca_file"))
        if not api.get("verify_tls", True) or endpoint:
            # Through a tunnel the URL says 127.0.0.1, which won't match the cert's
            # name. The tunnel is already authenticated by ssh.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        if api.get("cert_file"):
            ctx.load_cert_chain(api["cert_file"], api.get("key_file"))

    try:
        with urllib.request.urlopen(req, timeout=server.settings["timeout"], context=ctx) as resp:
            payload = json.loads(resp.read())
            date_hdr = resp.headers.get("Date")
    except urllib.error.HTTPError as e:
        hint = ""
        if e.code in (401, 403):
            hint = " (check api.username / password_env and the server's authentication settings)"
        raise CollectError(f"{server.name}: HTTP {e.code} from {url}{hint}: {e.read()[:200]!r}") from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        where = url
        if endpoint:
            where = (f"{api['tunnel_host']}:{api['port']} via ssh tunnel ({e}; is the API listening "
                     f"there, and does sshd allow TCP forwarding?)")
            raise CollectError(f"{server.name}: cannot reach Kea API at {where}") from e
        raise CollectError(f"{server.name}: cannot reach Kea API at {where}: {e}") from e

    # The control agent wraps responses in a list (one per service); the DHCP
    # daemon's own listener returns a bare object.
    if isinstance(payload, list):
        if not payload:
            raise CollectError(f"{server.name}: empty response to {command}")
        payload = payload[0]
    return payload, date_hdr


def _collect_api_pages(server, family, endpoint):
    cmd = f"lease{family}-get-page"
    page_size = server.settings["api"]["page_size"]
    leases = {}
    cursor = "start"
    started = time.time()
    server_time = None
    while True:
        resp, date_hdr = api_call(server, family, cmd, {"from": cursor, "limit": page_size}, endpoint)
        if server_time is None and date_hdr:
            server_time = _parse_http_date(date_hdr)
        result = resp.get("result")
        if result == 3:      # empty: no more leases
            break
        if result != 0:
            hint = ""
            if "not supported" in str(resp.get("text", "")).lower() or result == 2:
                hint = " (is the lease_cmds hook library loaded?)"
            raise CollectError(f"{server.name}: {cmd} failed: {resp.get('text')}{hint}")
        page = resp.get("arguments", {}).get("leases", [])
        for item in page:
            ls = lease_mod.from_api(family, item)
            leases[ls.key] = ls
        if len(page) < page_size:
            break
        cursor = page[-1]["ip-address"]
    return Snapshot(server, family, leases, started, time.time(), server_time)


def _parse_http_date(value):
    from email.utils import parsedate_to_datetime
    try:
        return parsedate_to_datetime(value).timestamp()
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- SSH

_MARK = "@@KEA-LEASE-AUDIT@@"


def _collect_ssh(server, family):
    s = server.settings["ssh"]
    base = s["lease_dir"].rstrip("/") + "/" + s[f"lease_file{family}"]
    candidates = [base, base + ".1", base + ".2", base + ".completed"]
    # One remote shell: record the server clock, then dump every journal file
    # that exists, each prefixed with a marker line naming it.
    script = f"date +%s; for f in {' '.join(shlex.quote(c) for c in candidates)}; do " \
             f"if [ -f \"$f\" ]; then echo \"{_MARK} $f\"; cat \"$f\"; fi; done"
    remote = f"sh -c {shlex.quote(script)}"
    if s.get("sudo"):
        remote = "sudo -n " + remote

    started = time.time()
    proc = sshconn.run(server, remote, timeout=server.settings["timeout"] * 4)
    finished = time.time()
    if proc.returncode != 0:
        raise CollectError(f"{server.name}: ssh failed ({proc.returncode}): {proc.stderr.strip()}")

    lines = proc.stdout.split("\n")
    try:
        server_time = float(lines[0].strip())
    except (IndexError, ValueError):
        server_time = None
    files, current = {}, None
    for line in lines[1:]:
        if line.startswith(_MARK + " "):
            current = line[len(_MARK) + 1:]
            files[current] = []
        elif current is not None:
            files[current].append(line)
    if base not in files:
        raise CollectError(f"{server.name}: lease file {base} not found (check ssh.lease_dir / permissions)")

    texts = ["\n".join(files[f]) for f in memfile.load_order(base, set(files))]
    return Snapshot(server, family, memfile.replay(family, texts), started, finished, server_time)
