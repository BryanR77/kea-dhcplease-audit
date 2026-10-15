"""Parse Kea memfile (CSV) lease files into normalized lease records.

The memfile backend is an append-only journal: every add/update/delete of a
lease appends a row, and the last row for a given address wins. A row with
valid_lifetime == 0 records a deletion. The Lease File Cleanup (LFC) process
periodically compacts the journal, which produces these companion files:

    <name>.2          previous journal being cleaned up (input to LFC)
    <name>.1          journal that was active when LFC started
    <name>.output     LFC work in progress (ignored, Kea ignores it too)
    <name>.completed  finished LFC result, replaces .1 and .2

Kea loads them in the order below on startup, and we do the same so the result
matches what the server holds in memory.
"""

import csv
import io

from .lease import Lease


def load_order(base, available):
    """Return the files to replay, oldest first, mirroring Kea's own startup logic."""
    if base + ".completed" in available:
        order = [base + ".completed"]
    else:
        order = [base + ".2", base + ".1"]
    order.append(base)
    return [f for f in order if f in available]


def _unescape(value):
    # Kea escapes commas in text fields as "&#x2c" so the CSV stays one-column-per-field.
    return value.replace("&#x2c", ",")


def _int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _bool(value):
    return value.strip().lower() in ("1", "true", "yes")


def _row_to_lease(family, row):
    valid = _int(row.get("valid_lifetime"))
    expire = _int(row.get("expire"))
    if family == 4:
        return Lease(
            family=4,
            address=row["address"].strip(),
            lease_type="V4",
            prefix_len=32,
            hwaddr=row.get("hwaddr", "").strip().lower(),
            client_id=row.get("client_id", "").strip().lower(),
            iaid=None,
            valid_lft=valid,
            cltt=expire - valid,
            subnet_id=_int(row.get("subnet_id")),
            fqdn_fwd=_bool(row.get("fqdn_fwd", "0")),
            fqdn_rev=_bool(row.get("fqdn_rev", "0")),
            hostname=_unescape(row.get("hostname", "")).strip().lower(),
            state=_int(row.get("state")),
        )
    lease_type = {"0": "IA_NA", "1": "IA_TA", "2": "IA_PD"}.get(row.get("lease_type", "0").strip(), "IA_NA")
    return Lease(
        family=6,
        address=row["address"].strip(),
        lease_type=lease_type,
        prefix_len=_int(row.get("prefix_len"), 128),
        hwaddr=row.get("hwaddr", "").strip().lower(),
        client_id=row.get("duid", "").strip().lower(),
        iaid=_int(row.get("iaid")),
        valid_lft=valid,
        cltt=expire - valid,
        subnet_id=_int(row.get("subnet_id")),
        fqdn_fwd=_bool(row.get("fqdn_fwd", "0")),
        fqdn_rev=_bool(row.get("fqdn_rev", "0")),
        hostname=_unescape(row.get("hostname", "")).strip().lower(),
        state=_int(row.get("state")),
    )


def replay(family, texts):
    """Replay journal texts (oldest first) and return {key: Lease} of current leases."""
    leases = {}
    for text in texts:
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            if not row.get("address"):
                continue
            if None in row.values() or None in row:
                continue  # short/long row: a line caught mid-write by a concurrent append
            try:
                lease = _row_to_lease(family, row)
            except (KeyError, AttributeError):
                continue  # truncated trailing line from a write in progress
            if lease.valid_lft == 0:
                leases.pop(lease.key, None)
            else:
                leases[lease.key] = lease
    return leases
