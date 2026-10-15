"""N-way comparison of lease snapshots from servers in one region.

Why timing is less fragile than it first looks: HA replicates each lease to
its partner with the *same* cltt and valid-lft, as absolute timestamps. So two
in-sync servers hold byte-identical lease data, and clock skew between them
does not show up in the data. Time only matters in two places:

  1. Expiry. Each server reclaims expired leases on its own timer, so a lease
     that just expired may be gone on one server and still present on the
     other. We only compare leases that are live somewhere beyond `expiry_grace`.

  2. In-flight updates. A lease that changed during the fetch may have reached
     one server but not yet its partner. Differences whose newest cltt falls
     inside `settle_window` of the fetch are treated as transient, and every
     difference must survive `recheck_rounds` re-fetches before it is reported.
"""

from dataclasses import dataclass, field

COMPARED_FIELDS = ("hwaddr", "client_id", "iaid", "subnet_id", "valid_lft", "cltt",
                   "hostname", "fqdn_fwd", "fqdn_rev", "state")


@dataclass
class Discrepancy:
    family: int
    key: tuple
    kind: str                      # missing | stale | mismatch
    records: dict                  # server name -> Lease or None
    fields: list = field(default_factory=list)

    @property
    def address(self):
        addr, ltype, plen = self.key
        return f"{addr}/{plen}" if ltype == "IA_PD" else addr

    def signature(self):
        """Stable identity used to check a discrepancy persists across rounds."""
        return (self.family, self.key, self.kind)


def compare(snapshots, settings):
    """Compare snapshots (one per server, same family). Returns (discrepancies, stats)."""
    grace = settings["expiry_grace"]
    tolerance = settings["time_tolerance"]
    settle = settings["settle_window"]
    ignore = set(settings.get("ignore_fields") or [])
    fields_to_check = [f for f in COMPARED_FIELDS if f not in ignore]

    family = snapshots[0].family
    # "now" is the earliest fetch start: anything changed after it is in flight.
    now = min(s.started for s in snapshots)
    in_flight_after = now - settle
    names = [s.server.name for s in snapshots]

    all_keys = set()
    for s in snapshots:
        all_keys.update(s.leases)

    discrepancies = []
    stats = {"compared": 0, "skipped_expired": 0, "transient": 0}
    for key in sorted(all_keys):
        recs = {s.server.name: s.leases.get(key) for s in snapshots}
        present = [r for r in recs.values() if r is not None]

        # Ignore leases that are not clearly live on any server: expiry and
        # reclamation run independently per server.
        if not any(r.is_live(now + grace) for r in present):
            stats["skipped_expired"] += 1
            continue
        stats["compared"] += 1

        d = _diff(family, key, recs, names, fields_to_check, tolerance, now - grace)
        if d is None:
            continue
        if max(r.cltt for r in present) >= in_flight_after:
            stats["transient"] += 1
            continue
        discrepancies.append(d)
    return discrepancies, stats


def _diff(family, key, recs, names, fields_to_check, tolerance, expired_before):
    present = {n: r for n, r in recs.items() if r is not None}
    # A copy that has expired/been reclaimed counts as absent: the partner that
    # still shows it live is the one with information the other lacks.
    live = {n: r for n, r in present.items() if r.is_live(expired_before)}
    if len(live) < len(names):
        # If every copy is present but some are stale-expired while another
        # was renewed, call it stale, not missing.
        kind = "stale" if len(present) == len(names) else "missing"
        return Discrepancy(family, key, kind, recs, ["cltt"] if kind == "stale" else [])

    ref = next(iter(live.values()))
    diffs = []
    for f in fields_to_check:
        values = [getattr(r, f) for r in live.values()]
        if f == "cltt":
            if max(values) - min(values) > tolerance:
                diffs.append(f)
        elif any(v != getattr(ref, f) for v in values):
            diffs.append(f)
    if not diffs:
        return None
    # A cltt/valid-lft-only difference means one server missed a renewal.
    kind = "stale" if set(diffs) <= {"cltt", "valid_lft"} else "mismatch"
    return Discrepancy(family, key, kind, recs, diffs)
