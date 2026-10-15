# kea-lease-audit

Checks that the Kea DHCP servers in each HA region hold the same lease database.
Run it from any host that can reach the servers. It needs Python 3.9+ and PyYAML.

    cp servers.example.yaml servers.yaml   # edit regions/servers
    python3 -m kea_lease_audit -c servers.yaml          # text report
    python3 -m kea_lease_audit -c servers.yaml --json   # machine-readable
    python3 -m kea_lease_audit -r home                  # a single region

Exit codes: `0` in sync, `1` discrepancies found, `2` a server could not be read.
That makes it usable from cron or as a Nagios-style check.

## Collection methods

| method | how | server needs |
|---|---|---|
| `api` (default) | `lease4-get-page` / `lease6-get-page`, paged | `libdhcp_lease_cmds.so` hook; Control Agent (or Kea 3.x daemon HTTP listener) reachable from the auditor |
| `ssh` | one `ssh` session that prints the server clock and the memfile journals (`.csv`, `.csv.1`, `.csv.2`, `.csv.completed`), which are replayed locally the way Kea loads them | key-based SSH; read access to `/var/lib/kea` (or `sudo -n`) |

The API reads what the server holds in memory and works with any lease backend.
SSH needs no Kea changes, but it only works with the memfile backend.

### API over an SSH tunnel (loopback-only servers)

If the API listens only on `127.0.0.1`, set `api.tunnel: true`. The tool opens
`ssh -N -L <free local port>:127.0.0.1:<api.port>` to each server, using the
`ssh` settings for user, key and options. It runs the same paged API queries
through the tunnel, then closes it. The SSH user only needs to log in. It does
not need read access to `/var/lib/kea`. The server's sshd must allow TCP
forwarding for that user, for example with a `Match User kea-audit` block that has
`AllowTcpForwarding local` and `PermitOpen 127.0.0.1:8000`.
If forwarding is not allowed, use `method: ssh` instead.

Version notes:

* Kea 2.6.x: the API is the Control Agent (default port 8000). Use `service: true`.
* Kea 3.x: kea-dhcp4 serves the API itself. Use `service: null` and that listener's port.

## Timing

HA copies each lease to its partner with the same absolute `cltt` and
`valid-lft`, so clock skew between peers does not affect the comparison. The tool
only has to handle leases that changed while it was reading them:

* Every server in a region is read in parallel.
* A lease is compared only if at least one server shows it live past
  `expiry_grace`, because each server reclaims expired leases on its own timer.
* A difference on a lease whose newest `cltt` is within `settle_window` of the
  read counts as in flight and is not reported.
* Any remaining difference is re-read after `recheck_delay`, and it is reported
  only if it persists through `recheck_rounds`.

The report also shows each server's clock offset from the auditor, which is
worth watching on its own.

## Discrepancy kinds

* **missing**: a live lease on some servers is absent (or expired/released) on others
* **stale**: same client, but `cltt`/`valid_lft` differ, so one peer missed a renewal
* **mismatch**: other fields differ (hwaddr, client-id/DUID, subnet, hostname, state…)

## Tests

    python3 -m unittest -v

## License

MIT. See [LICENSE](LICENSE).
