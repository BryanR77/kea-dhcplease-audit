import io
import json
import os
import stat
import tempfile
import threading
import time
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer

from kea_lease_audit import cli, compare, config, memfile
from kea_lease_audit.collectors import Snapshot

V4_HEADER = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context,pool_id\n"
NOW = int(time.time())


def row(addr, hw="aa:bb:cc:dd:ee:01", valid=3600, cltt=NOW - 600, host="host", state=0, subnet=1):
    return f"{addr},{hw},01:{hw},{valid},{cltt + valid},{subnet},0,0,{host},{state},,0\n"


def api_lease(addr, hw="aa:bb:cc:dd:ee:01", valid=3600, cltt=NOW - 600, host="host", state=0, subnet=1):
    return {"ip-address": addr, "hw-address": hw, "client-id": f"01:{hw}", "valid-lft": valid,
            "cltt": cltt, "subnet-id": subnet, "fqdn-fwd": False, "fqdn-rev": False,
            "hostname": host, "state": state}


class FakeServer:
    def __init__(self, name):
        self.name = name


def snap(name, rows, started=NOW):
    leases = memfile.replay(4, [V4_HEADER + "".join(rows)])
    return Snapshot(FakeServer(name), 4, leases, started, started + 1)


SETTINGS = dict(config.BUILTIN_DEFAULTS["compare"])


class MemfileTests(unittest.TestCase):
    def test_last_row_wins_and_delete(self):
        text = V4_HEADER + row("10.0.0.1", cltt=NOW - 900) + row("10.0.0.1", cltt=NOW - 100) \
            + row("10.0.0.2") + row("10.0.0.2", valid=0)
        leases = memfile.replay(4, [text])
        self.assertEqual(list(leases), [("10.0.0.1", "V4", 32)])
        self.assertEqual(leases[("10.0.0.1", "V4", 32)].cltt, NOW - 100)

    def test_truncated_line_ignored(self):
        text = V4_HEADER + row("10.0.0.1") + "10.0.0.1,aa:bb"
        leases = memfile.replay(4, [text])
        self.assertEqual(leases[("10.0.0.1", "V4", 32)].valid_lft, 3600)

    def test_escaped_comma_in_hostname(self):
        leases = memfile.replay(4, [V4_HEADER + row("10.0.0.1", host="a&#x2cb")])
        self.assertEqual(leases[("10.0.0.1", "V4", 32)].hostname, "a,b")

    def test_lfc_load_order(self):
        b = "/var/lib/kea/kea-leases4.csv"
        self.assertEqual(memfile.load_order(b, {b, b + ".1", b + ".2"}), [b + ".2", b + ".1", b])
        self.assertEqual(memfile.load_order(b, {b, b + ".completed", b + ".2"}), [b + ".completed", b])


class CompareTests(unittest.TestCase):
    def test_identical(self):
        rows = [row("10.0.0.1"), row("10.0.0.2", hw="aa:bb:cc:dd:ee:02")]
        ds, stats = compare.compare([snap("a", rows), snap("b", rows)], SETTINGS)
        self.assertEqual(ds, [])
        self.assertEqual(stats["compared"], 2)

    def test_missing(self):
        ds, _ = compare.compare([snap("a", [row("10.0.0.1")]), snap("b", [])], SETTINGS)
        self.assertEqual([(d.address, d.kind) for d in ds], [("10.0.0.1", "missing")])

    def test_stale_renewal(self):
        ds, _ = compare.compare([snap("a", [row("10.0.0.1", cltt=NOW - 300)]),
                                 snap("b", [row("10.0.0.1", cltt=NOW - 2000)])], SETTINGS)
        self.assertEqual([(d.kind, d.fields) for d in ds], [("stale", ["cltt"])])

    def test_mismatched_client(self):
        ds, _ = compare.compare([snap("a", [row("10.0.0.1", hw="aa:aa:aa:aa:aa:aa")]),
                                 snap("b", [row("10.0.0.1", hw="bb:bb:bb:bb:bb:bb")])], SETTINGS)
        self.assertEqual(ds[0].kind, "mismatch")
        self.assertIn("hwaddr", ds[0].fields)

    def test_expired_on_both_ignored_even_if_reclaimed_on_one(self):
        old = NOW - 10000
        ds, stats = compare.compare([snap("a", [row("10.0.0.1", cltt=old)]),
                                     snap("b", [row("10.0.0.1", cltt=old, state=2)])], SETTINGS)
        self.assertEqual(ds, [])
        self.assertEqual(stats["skipped_expired"], 1)

    def test_lease_expiring_within_grace_ignored(self):
        ds, _ = compare.compare([snap("a", [row("10.0.0.1", valid=600, cltt=NOW - 580)]),
                                 snap("b", [])], SETTINGS)
        self.assertEqual(ds, [])

    def test_in_flight_is_transient(self):
        ds, stats = compare.compare([snap("a", [row("10.0.0.1", cltt=NOW - 2)]), snap("b", [])], SETTINGS)
        self.assertEqual(ds, [])
        self.assertEqual(stats["transient"], 1)

    def test_three_way(self):
        rows = [row("10.0.0.1")]
        ds, _ = compare.compare([snap("a", rows), snap("b", rows), snap("c", [])], SETTINGS)
        self.assertEqual(len(ds), 1)
        self.assertIsNone(ds[0].records["c"])

    def test_ignore_fields(self):
        s = dict(SETTINGS, ignore_fields=["hostname"])
        ds, _ = compare.compare([snap("a", [row("10.0.0.1", host="x")]),
                                 snap("b", [row("10.0.0.1", host="y")])], s)
        self.assertEqual(ds, [])


class ConfigTests(unittest.TestCase):
    def test_cascade(self):
        regions = config.parse({
            "defaults": {"api": {"port": 9000}},
            "regions": {"r1": {"method": "ssh", "servers": [
                {"host": "a.example"}, {"host": "b.example", "ssh": {"user": "x"}}]}},
        })
        a, b = regions[0].servers
        self.assertEqual((a.name, a.method, a.settings["api"]["port"]), ("a", "ssh", 9000))
        self.assertEqual(b.settings["ssh"]["user"], "x")
        self.assertIsNone(a.settings["ssh"]["user"])

    def test_identity_file_checked_and_expanded(self):
        doc = lambda key: {"regions": {"r": {"method": "ssh", "ssh": {"identity_file": key},
                                             "servers": [{"host": "a"}, {"host": "b"}]}}}
        with self.assertRaisesRegex(config.ConfigError, "does not exist"):
            config.parse(doc("/nonexistent/key"))
        with tempfile.NamedTemporaryFile() as fh:
            os.chmod(fh.name, 0o644)
            with self.assertRaisesRegex(config.ConfigError, "chmod 600"):
                config.parse(doc(fh.name))
            os.chmod(fh.name, 0o600)
            os.environ["KEA_TEST_KEY"] = fh.name
            self.addCleanup(os.environ.pop, "KEA_TEST_KEY")
            server = config.parse(doc("$KEA_TEST_KEY"))[0].servers[0]
            self.assertEqual(server.settings["ssh"]["identity_file"], fh.name)
            from kea_lease_audit.collectors import _ssh_base
            self.assertIn("IdentitiesOnly=yes", _ssh_base(server))
        # Not checked when ssh isn't used.
        config.parse({"regions": {"r": {"ssh": {"identity_file": "/nonexistent"},
                                        "servers": [{"host": "a"}, {"host": "b"}]}}})

    def test_needs_two_servers(self):
        with self.assertRaises(config.ConfigError):
            config.parse({"regions": {"r": {"servers": [{"host": "a"}]}}})


def make_kea_handler(leases):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            req = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            assert req["command"] == "lease4-get-page" and req["service"] == ["dhcp4"]
            args = req["arguments"]
            ordered = sorted(leases, key=lambda l: tuple(int(o) for o in l["ip-address"].split(".")))
            if args["from"] != "start":
                start = tuple(int(o) for o in args["from"].split("."))
                ordered = [l for l in ordered if tuple(int(o) for o in l["ip-address"].split(".")) > start]
            page = ordered[:args["limit"]]
            resp = {"result": 0, "text": "ok", "arguments": {"leases": page, "count": len(page)}} \
                if page else {"result": 3, "text": "0 IPv4 lease(s) found."}
            body = json.dumps([resp]).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
    return Handler


FAKE_SSH_FORWARDER = """#!/usr/bin/env python3
import socket, sys, threading
args = sys.argv[1:]
spec = args[args.index("-L") + 1]
_, lport, rhost, rport = spec.split(":")
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", int(lport)))
srv.listen()
def pipe(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        # shutdown, not close: close() won't send FIN while the other
        # direction's thread is still blocked in recv() on this socket.
        try:
            b.shutdown(socket.SHUT_WR)
        except OSError:
            pass
while True:
    c, _ = srv.accept()
    u = socket.create_connection((rhost, int(rport)))
    threading.Thread(target=pipe, args=(c, u), daemon=True).start()
    threading.Thread(target=pipe, args=(u, c), daemon=True).start()
"""


class EndToEndTests(unittest.TestCase):
    def _run(self, cfg, *extra):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
            json.dump(cfg, fh)  # JSON is valid YAML
        out = io.StringIO()
        try:
            with redirect_stdout(out):
                rc = cli.main(["-c", fh.name, "-q", "--json", *extra])
        finally:
            os.unlink(fh.name)
        return rc, json.loads(out.getvalue())

    def test_api_paging_and_drift(self):
        common = [api_lease(f"10.0.0.{i}", hw=f"aa:bb:cc:dd:ee:{i:02x}") for i in range(1, 8)]
        servers = []
        for extra in ([], [api_lease("10.0.0.50")]):
            httpd = HTTPServer(("127.0.0.1", 0), make_kea_handler(common + extra))
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            self.addCleanup(httpd.server_close)
            self.addCleanup(httpd.shutdown)
            servers.append({"host": "127.0.0.1", "name": f"s{len(servers)}",
                            "api": {"port": httpd.server_address[1]}})
        cfg = {"defaults": {"api": {"page_size": 3}, "compare": {"recheck_delay": 0}},
               "regions": {"lab": {"servers": servers}}}
        rc, doc = self._run(cfg)
        self.assertEqual(rc, cli.EXIT_DRIFT)
        r = doc["lab"][0]
        self.assertEqual(r["live_counts"], {"s0": 7, "s1": 8})
        self.assertEqual([(d["address"], d["kind"]) for d in r["discrepancies"]], [("10.0.0.50", "missing")])

    def test_ssh_with_fake_ssh_binary(self):
        tmp = tempfile.mkdtemp()
        bindir = os.path.join(tmp, "bin")
        os.mkdir(bindir)
        fake = os.path.join(bindir, "ssh")
        # Fake ssh: ignore options/target and run the remote command locally.
        with open(fake, "w") as fh:
            fh.write('#!/bin/sh\nfor last; do :; done\nexec sh -c "$last"\n')
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
        for name, extra in (("n1", ""), ("n2", row("10.0.0.9"))):
            d = os.path.join(tmp, name)
            os.mkdir(d)
            # n1 is mid-LFC: older data in .2, newer in the live file.
            with open(os.path.join(d, "kea-leases4.csv.2"), "w") as fh:
                fh.write(V4_HEADER + row("10.0.0.1", cltt=NOW - 5000))
            with open(os.path.join(d, "kea-leases4.csv"), "w") as fh:
                fh.write(V4_HEADER + row("10.0.0.1") + extra)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = bindir + os.pathsep + old_path
        self.addCleanup(os.environ.__setitem__, "PATH", old_path)
        cfg = {"defaults": {"method": "ssh", "compare": {"recheck_delay": 0}},
               "regions": {"lab": {"servers": [
                   {"host": "n1", "ssh": {"lease_dir": os.path.join(tmp, "n1")}},
                   {"host": "n2", "ssh": {"lease_dir": os.path.join(tmp, "n2")}}]}}}
        rc, doc = self._run(cfg)
        r = doc["lab"][0]
        self.assertEqual(rc, cli.EXIT_DRIFT)
        self.assertEqual([d["address"] for d in r["discrepancies"]], ["10.0.0.9"])
        self.assertLess(abs(r["clock_offsets"]["n1"]), 3)

    def _fake_ssh_dir(self, script):
        bindir = tempfile.mkdtemp()
        fake = os.path.join(bindir, "ssh")
        with open(fake, "w") as fh:
            fh.write(script)
        os.chmod(fake, os.stat(fake).st_mode | stat.S_IEXEC)
        old_path = os.environ["PATH"]
        os.environ["PATH"] = bindir + os.pathsep + old_path
        self.addCleanup(os.environ.__setitem__, "PATH", old_path)

    def _fake_kea(self, leases):
        httpd = HTTPServer(("127.0.0.1", 0), make_kea_handler(leases))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.server_close)
        self.addCleanup(httpd.shutdown)
        return httpd.server_address[1]

    def test_api_over_ssh_tunnel(self):
        # Fake ssh that implements -L by forwarding connections to the target.
        self._fake_ssh_dir(FAKE_SSH_FORWARDER)
        common = [api_lease("10.0.0.1")]
        p1 = self._fake_kea(common)
        p2 = self._fake_kea(common + [api_lease("10.0.0.2", hw="aa:aa:aa:aa:aa:02")])
        cfg = {"defaults": {"api": {"tunnel": True}, "compare": {"recheck_delay": 0}},
               "regions": {"prod": {"servers": [
                   {"host": "dhcp1.example", "api": {"port": p1}},
                   {"host": "dhcp2.example", "api": {"port": p2}}]}}}
        rc, doc = self._run(cfg)
        self.assertEqual(rc, cli.EXIT_DRIFT, doc)
        r = doc["prod"][0]
        self.assertEqual(r["live_counts"], {"dhcp1": 1, "dhcp2": 2})
        self.assertEqual([d["address"] for d in r["discrepancies"]], ["10.0.0.2"])

    def test_tunnel_refused_is_error(self):
        self._fake_ssh_dir("#!/bin/sh\necho 'channel_setup_fwd_listener: administratively prohibited' >&2\nexit 255\n")
        cfg = {"defaults": {"api": {"tunnel": True}},
               "regions": {"prod": {"servers": [{"host": "a"}, {"host": "b"}]}}}
        rc, doc = self._run(cfg)
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("administratively prohibited", doc["prod"][0]["error"])

    def test_unreachable_is_error(self):
        cfg = {"defaults": {"timeout": 2, "api": {"port": 1}},
               "regions": {"lab": {"servers": [{"host": "127.0.0.1", "name": "a"},
                                               {"host": "127.0.0.1", "name": "b"}]}}}
        rc, doc = self._run(cfg)
        self.assertEqual(rc, cli.EXIT_ERROR)
        self.assertIn("cannot reach", doc["lab"][0]["error"])


if __name__ == "__main__":
    unittest.main()
