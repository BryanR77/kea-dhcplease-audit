"""Command-line entry point: audit every region in the inventory."""

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from . import collectors, compare, config

EXIT_OK, EXIT_DRIFT, EXIT_ERROR = 0, 1, 2


def snapshot_region(region, family):
    """Fetch all servers in a region at the same time to keep the snapshots close together."""
    with ThreadPoolExecutor(max_workers=len(region.servers)) as pool:
        futures = [pool.submit(collectors.collect, s, family) for s in region.servers]
        return [f.result() for f in futures]


def audit_region(region, family, log):
    settings = region.compare
    snaps = snapshot_region(region, family)
    found, stats = compare.compare(snaps, settings)
    first_snaps = snaps
    log(f"  [{region.name} v{family}] round 1: {len(found)} candidate discrepancies "
        f"({stats['compared']} live leases compared)")

    rounds = int(settings["recheck_rounds"])
    for i in range(rounds):
        if not found:
            break
        time.sleep(settings["recheck_delay"])
        snaps = snapshot_region(region, family)
        again, _ = compare.compare(snaps, settings)
        persistent = {d.signature() for d in found}
        found = [d for d in again if d.signature() in persistent]
        log(f"  [{region.name} v{family}] recheck {i + 1}: {len(found)} persist")

    offsets = {s.server.name: s.clock_offset for s in first_snaps}
    counts = {s.server.name: sum(1 for l in s.leases.values() if l.is_live(s.started))
              for s in first_snaps}
    return {"family": family, "stats": stats, "live_counts": counts,
            "clock_offsets": offsets, "discrepancies": found}


def _fmt_ts(ts):
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def _describe(rec, fields):
    if rec is None:
        return "(absent)"
    parts = []
    show = fields or ["hwaddr", "cltt"]
    for f in show:
        v = getattr(rec, f)
        if f == "cltt":
            parts.append(f"cltt={_fmt_ts(v)} expire={_fmt_ts(rec.expire)}")
        else:
            parts.append(f"{f}={v!r}")
    if "state" not in show and rec.state:
        parts.append(f"state={rec.state}")
    return " ".join(parts)


def render_text(results, out):
    for region_name, fam_results in results.items():
        for r in fam_results:
            if "error" in r:
                print(f"\n[{region_name}] DHCPv{r['family']}: ERROR {r['error']}", file=out)
                continue
            ds = r["discrepancies"]
            status = "IN SYNC" if not ds else f"{len(ds)} DISCREPANCIES"
            print(f"\n[{region_name}] DHCPv{r['family']}: {status}", file=out)
            counts = ", ".join(f"{n}={c}" for n, c in r["live_counts"].items())
            print(f"  live leases: {counts}", file=out)
            st = r["stats"]
            print(f"  compared {st['compared']}, skipped {st['skipped_expired']} expired, "
                  f"{st['transient']} in-flight", file=out)
            offs = [f"{n}={o:+.0f}s" for n, o in r["clock_offsets"].items() if o is not None]
            if offs:
                print(f"  clock offset vs auditor: {', '.join(offs)}", file=out)
            for d in ds:
                print(f"  - {d.address} {d.kind}" + (f" [{','.join(d.fields)}]" if d.fields else ""),
                      file=out)
                for name, rec in d.records.items():
                    print(f"      {name:<16} {_describe(rec, d.fields)}", file=out)


def render_json(results, out):
    doc = {}
    for region_name, fam_results in results.items():
        doc[region_name] = []
        for r in fam_results:
            if "error" in r:
                doc[region_name].append(r)
                continue
            doc[region_name].append({
                **{k: v for k, v in r.items() if k != "discrepancies"},
                "in_sync": not r["discrepancies"],
                "discrepancies": [{
                    "address": d.address, "kind": d.kind, "fields": d.fields,
                    "records": {n: (rec.to_dict() if rec else None) for n, rec in d.records.items()},
                } for d in r["discrepancies"]],
            })
    json.dump(doc, out, indent=2)
    out.write("\n")


def main(argv=None):
    p = argparse.ArgumentParser(prog="kea-lease-audit",
                                description="Verify Kea HA peers hold identical lease databases.")
    p.add_argument("-c", "--config", default="servers.yaml", help="inventory YAML (default: servers.yaml)")
    p.add_argument("-r", "--region", action="append", help="only audit this region (repeatable)")
    p.add_argument("--json", action="store_true", help="emit JSON instead of text")
    p.add_argument("--no-recheck", action="store_true", help="report first-round results without rechecking")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress output on stderr")
    args = p.parse_args(argv)

    try:
        regions = config.load(args.config)
    except (OSError, config.ConfigError) as e:
        print(f"config error: {e}", file=sys.stderr)
        return EXIT_ERROR
    if args.region:
        wanted = set(args.region)
        unknown = wanted - {r.name for r in regions}
        if unknown:
            print(f"unknown region(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return EXIT_ERROR
        regions = [r for r in regions if r.name in wanted]

    log = (lambda msg: None) if args.quiet else (lambda msg: print(msg, file=sys.stderr))
    results, errors, drift = {}, False, False
    for region in regions:
        if args.no_recheck:
            region.compare["recheck_rounds"] = 0
        families = sorted({f for s in region.servers for f in s.settings["families"]})
        log(f"auditing {region.name}: {', '.join(s.name for s in region.servers)}")
        results[region.name] = []
        for fam in families:
            try:
                r = audit_region(region, fam, log)
                drift |= bool(r["discrepancies"])
            except collectors.CollectError as e:
                r = {"family": fam, "error": str(e)}
                errors = True
            results[region.name].append(r)

    (render_json if args.json else render_text)(results, sys.stdout)
    if errors:
        return EXIT_ERROR
    return EXIT_DRIFT if drift else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
