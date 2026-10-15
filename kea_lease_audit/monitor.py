"""Turn audit and HA results into monitoring checks (Nagios plugin / CheckMK local check).

Nagios plugin output (also used by LibreNMS services, Icinga, CheckMK
"classical" active checks): first line is "<STATE> - summary | perfdata",
further lines are details, exit code is the state.

CheckMK local check output: one line per service,
  <state> "<service name>" <metric>=<value>;<warn>;<crit>|... <summary>\\n<details>
and the exit code doesn't matter.
"""

import re
from dataclasses import dataclass, field

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
STATE_NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}
# Severity order for "worst of": UNKNOWN outranks WARNING but not CRITICAL.
_RANK = {OK: 0, WARNING: 1, UNKNOWN: 2, CRITICAL: 3}


def worst(states):
    return max(states, key=_RANK.__getitem__, default=OK)


@dataclass
class Metric:
    name: str
    value: float
    warn: object = None
    crit: object = None
    minimum: object = None


@dataclass
class Check:
    service: str
    state: int
    summary: str
    metrics: list = field(default_factory=list)
    details: list = field(default_factory=list)


def _label(text):
    return re.sub(r"[^A-Za-z0-9_]+", "_", text).strip("_").lower()


def lease_check(region_name, result, warn, crit, clock_warn):
    fam = result["family"]
    service = f"Kea leases {region_name} v{fam}"
    if "error" in result:
        return Check(service, UNKNOWN, f"could not audit: {result['error']}")

    ds = result["discrepancies"]
    n = len(ds)
    state = CRITICAL if n >= crit else WARNING if n >= warn else OK
    parts = [f"{n} discrepanc{'y' if n == 1 else 'ies'}" if n else "in sync"]
    counts = result["live_counts"]
    parts.append("live " + ", ".join(f"{k}={v}" for k, v in counts.items()))
    details = []
    for d in ds[:20]:
        holders = [name for name, rec in d.records.items() if rec is not None]
        details.append(f"{d.address} {d.kind}" + (f" [{','.join(d.fields)}]" if d.fields else "")
                       + f" (present on {', '.join(holders) or 'none'})")
    if n > 20:
        details.append(f"... and {n - 20} more")

    for name, off in result["clock_offsets"].items():
        if off is not None and abs(off) > clock_warn:
            state = worst([state, WARNING])
            details.insert(0, f"{name} clock is {off:+.0f}s off the monitoring host")

    st = result["stats"]
    metrics = [Metric("discrepancies", n, warn, crit, 0),
               Metric("compared", st["compared"], minimum=0),
               Metric("in_flight", st["transient"], minimum=0)]
    metrics += [Metric(f"live_{_label(k)}", v, minimum=0) for k, v in counts.items()]
    # Signed, so no thresholds: a plain "30" would flag any negative offset.
    metrics += [Metric(f"clock_offset_{_label(k)}", round(v, 1))
                for k, v in result["clock_offsets"].items() if v is not None]
    metrics.append(Metric("duration", round(result.get("duration", 0), 2), minimum=0))
    return Check(service, state, "; ".join(parts), metrics, details)


def ha_check(region_name, family, results, findings):
    service = f"Kea HA {region_name} v{family}"
    state = worst([f.level for f in findings])
    if findings:
        summary = "; ".join(f.text for f in sorted(findings, key=lambda f: -_RANK[f.level])[:3])
        if len(findings) > 3:
            summary += f"; +{len(findings) - 3} more"
    else:
        summary = ", ".join(f"{r.server.name}={'/'.join(map(str, r.states))}" for r in results)
    details = [f.text for f in findings]
    metrics = []
    for r in results:
        if r.unsent_updates is not None:
            metrics.append(Metric(f"unsent_updates_{_label(r.server.name)}", r.unsent_updates, minimum=0))
        for rel in r.relationships:
            for remote in rel["remotes"]:
                if isinstance(remote.get("age"), (int, float)):
                    metrics.append(Metric(f"partner_age_{_label(r.server.name)}", remote["age"], minimum=0))
    return Check(service, state, summary, metrics, details)


# ---------------------------------------------------------------- rendering

def _fmt(v):
    return "" if v is None else (f"{v:g}" if isinstance(v, float) else str(v))


def _perf(metrics, prefix=""):
    out = []
    for m in metrics:
        label = f"{prefix}{m.name}"
        out.append(f"{label}={_fmt(m.value)};{_fmt(m.warn)};{_fmt(m.crit)};{_fmt(m.minimum)}".rstrip(";"))
    return out


def render_nagios(checks, out):
    """One plugin result covering all checks; returns the exit code."""
    state = worst([c.state for c in checks])
    if len(checks) == 1:
        c = checks[0]
        head = f"{c.service.upper()} {STATE_NAMES[c.state]} - {c.summary}"
        perf = _perf(c.metrics)
        details = c.details
    else:
        bad = [c for c in checks if c.state != OK]
        head = (f"KEA {STATE_NAMES[state]} - "
                + ("; ".join(f"{c.service}: {c.summary}" for c in bad) if bad
                   else f"{len(checks)} checks OK"))
        perf = [p for c in checks for p in _perf(c.metrics, _label(c.service) + "_")]
        details = [f"[{STATE_NAMES[c.state]}] {c.service}: {c.summary}" for c in checks]
        details += [f"  {d}" for c in checks for d in c.details]
    head = head.replace("|", "/")
    print(head + (" | " + " ".join(perf) if perf else ""), file=out)
    for d in details:
        print(d.replace("|", "/"), file=out)
    return state


def render_checkmk(checks, out):
    for c in checks:
        metrics = "|".join(_perf(c.metrics)) or "-"
        text = c.summary
        if c.details:
            text += "\\n" + "\\n".join(c.details)
        print(f'{c.state} "{c.service}" {metrics} {text}', file=out)
    return 0
