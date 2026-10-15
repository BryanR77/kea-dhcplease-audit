"""Cheap HA health check from Kea's own view: status-get and ha-heartbeat.

This doesn't compare leases. It catches what causes lease drift - a peer that
lost contact, a server stuck syncing or in partner-down, DHCP service turned
off - in two small API calls per server, so it can run every minute.
"""

from dataclasses import dataclass, field

from . import collectors

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3

# Normal steady states for a server in an HA relationship.
OK_STATES = {"hot-standby", "load-balancing", "passive-backup", "backup"}
# Transitional or operator-initiated states: service continues but HA is not whole.
WARN_STATES = {"waiting", "syncing", "ready", "communication-recovery",
               "in-maintenance", "partner-in-maintenance"}
# The server believes its partner is gone, or HA has given up.
CRIT_STATES = {"partner-down", "terminated"}


@dataclass
class Finding:
    level: int
    text: str


@dataclass
class ServerHA:
    server: object
    family: int
    relationships: list = field(default_factory=list)  # [{mode, local, remote}]
    unsent_updates: object = None
    findings: list = field(default_factory=list)

    @property
    def states(self):
        return [r["local"].get("state") for r in self.relationships]


def collect(server, family, clock_warn):
    # Servers audited over ssh have their API on loopback only: tunnel to it.
    tunnel = bool(server.settings["api"].get("tunnel")) or server.method == "ssh"
    with collectors.api_endpoint(server, tunnel=tunnel) as ep:
        status, _ = collectors.api_call(server, family, "status-get", None, ep)
        heartbeat, _ = collectors.api_call(server, family, "ha-heartbeat", None, ep)

    if status.get("result") != 0:
        raise collectors.CollectError(f"{server.name}: status-get failed: {status.get('text')}")
    args = status.get("arguments") or {}
    out = ServerHA(server, family)

    dhcp = args.get("dhcp-state") or {}
    if dhcp.get("globally-disabled"):
        reasons = [k for k in ("disabled-by-user", "disabled-by-local-command",
                               "disabled-by-remote-command", "disabled-by-db-connection") if dhcp.get(k)]
        out.findings.append(Finding(CRITICAL, f"{server.name}: DHCP service disabled"
                                    + (f" ({', '.join(reasons)})" if reasons else "")))

    for rel in args.get("high-availability") or []:
        servers = rel.get("ha-servers") or {}
        local = servers.get("local") or {}
        remote = servers.get("remote")
        # Hub-and-spoke (Kea 2.7+) may list several remotes.
        remotes = remote if isinstance(remote, list) else ([remote] if remote else [])
        out.relationships.append({"mode": rel.get("ha-mode"), "local": local, "remotes": remotes})
        _grade_local(out, local)
        for r in remotes:
            _grade_remote(out, r, clock_warn)

    if not out.relationships:
        out.findings.append(Finding(WARNING, f"{server.name}: no HA relationship reported "
                                             f"(is libdhcp_ha.so loaded?)"))

    if heartbeat.get("result") == 0:
        out.unsent_updates = (heartbeat.get("arguments") or {}).get("unsent-update-count")
    return out


def _grade_local(out, local):
    name = out.server.name
    state = local.get("state")
    if state in OK_STATES:
        return
    if state in CRIT_STATES:
        out.findings.append(Finding(CRITICAL, f"{name}: HA state {state}"))
    elif state in WARN_STATES:
        out.findings.append(Finding(WARNING, f"{name}: HA state {state}"))
    else:
        out.findings.append(Finding(WARNING, f"{name}: unrecognised HA state {state!r}"))


def _grade_remote(out, remote, clock_warn):
    name, peer = out.server.name, remote.get("server-name", "partner")
    if remote.get("in-touch") is False:
        out.findings.append(Finding(CRITICAL, f"{name}: not in touch with {peer}"))
    if remote.get("communication-interrupted"):
        out.findings.append(Finding(WARNING, f"{name}: communication with {peer} interrupted "
                                             f"({remote.get('unacked-clients', 0)} unacked clients)"))
    skew = remote.get("clock-skew")
    if isinstance(skew, (int, float)) and abs(skew) > clock_warn:
        # Kea itself terminates HA at 60s of skew.
        level = CRITICAL if abs(skew) >= 60 else WARNING
        out.findings.append(Finding(level, f"{name}: clock skew with {peer} is {skew}s"))


def check_region(region, family, clock_warn):
    """Collect HA status from every server in a region and grade the region as a whole."""
    results, findings = [], []
    for server in region.servers:
        try:
            r = collect(server, family, clock_warn)
        except collectors.CollectError as e:
            findings.append(Finding(UNKNOWN, str(e)))
            continue
        results.append(r)
        findings.extend(r.findings)

    # Peers should agree on the mode (backup servers report "backup").
    primary_states = {s for r in results for s in r.states if s != "backup"}
    if len(primary_states) > 1:
        findings.append(Finding(WARNING, "peers disagree on HA state: "
                                + ", ".join(f"{r.server.name}={'/'.join(map(str, r.states))}"
                                            for r in results)))
    return results, findings
