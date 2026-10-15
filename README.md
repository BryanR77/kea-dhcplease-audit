# kea-lease-audit

Checks that the Kea DHCP servers in each HA region hold the same lease database.
Run it from any host that can reach the servers. It needs Python 3.9+ and PyYAML.

    cp servers.example.yaml servers.yaml   # edit regions/servers
    python3 -m kea_lease_audit -c servers.yaml          # text report
    python3 -m kea_lease_audit -c servers.yaml --json   # machine-readable
    python3 -m kea_lease_audit -r home                  # a single region
    python3 -m kea_lease_audit --check ha               # quick HA health check (see below)

Exit codes for text/JSON output: `0` in sync, `1` discrepancies found, `2` a
server could not be read. For monitoring systems, use `--output nagios` or
`--output checkmk` (see [Monitoring](#monitoring)).

## Installing

Each [release](https://github.com/BryanR77/kea-dhcplease-audit/releases) has a
wheel, an sdist, and `kea-lease-audit.pyz`. The `.pyz` is a single executable file
with PyYAML bundled. It needs only `python3` (3.9+), which makes it the easiest
way to put the tool on a monitoring host:

    curl -LO https://github.com/BryanR77/kea-dhcplease-audit/releases/latest/download/kea-lease-audit.pyz
    sudo install -m 755 kea-lease-audit.pyz /usr/local/bin/kea-lease-audit
    kea-lease-audit --version

You can also `pip install` the wheel from a release. Either way you get the
`kea-lease-audit` command that the [Monitoring](#monitoring) examples use.

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

## Monitoring

Two checks, meant to run at different intervals:

| check | what it does | cost per run | suggested interval |
|---|---|---|---|
| `--check ha` | `status-get` + `ha-heartbeat` on each server: HA state, partner contact, clock skew, DHCP service disabled | 2 small API calls per server | 1 min |
| `--check leases` (default) | full lease comparison | all leases, paged; about 3–8s of CPU on the monitoring host at 40–75k leases | 5–15 min |

The HA check catches what *causes* drift (a lost partner, stuck `syncing`,
`partner-down`) right away. The lease check proves the data actually matches.

The HA check grades states like this:

* OK: `hot-standby`, `load-balancing`, `passive-backup`, `backup`
* WARNING: `waiting`, `syncing`, `ready`, `communication-recovery`, maintenance
  states, communication interrupted, clock skew over `clock_warn`, peers disagreeing on state
* CRITICAL: `partner-down`, `terminated`, not in touch with the partner, DHCP
  service disabled, or clock skew of 60s or more (where Kea's own HA gives up)

For servers with `method: ssh`, the HA check reaches the API through an SSH
tunnel, using `api.port` and `api.tunnel_host`.

### Output formats

`--output nagios` prints a Nagios-plugin result. That is one status line with
perfdata, then detail lines, with exit codes 0 OK, 1 WARNING, 2 CRITICAL and
3 UNKNOWN (a server can't be read). LibreNMS services, Icinga, and CheckMK
classical checks use this format.

    KEA LEASES PROD V4 CRITICAL - 2 discrepancies; live dhcp1=41210, dhcp2=41208 | discrepancies=2;1;1;0 ...
    10.20.4.17 missing (present on dhcp1)

`--warn N` / `--crit N` set the discrepancy thresholds. Both default to 1, so
any persistent drift is CRITICAL.

`--output checkmk` prints CheckMK local-check lines, one service per region and
address family. CheckMK applies the state, so the exit code is always 0.

    0 "Kea leases prod v4" discrepancies=0;1;1;0|compared=41210;;;0|... in sync; live dhcp1=41210, dhcp2=41210

### SSH connection reuse

With `ssh.control_persist` (default 600 seconds), the first run starts a
background OpenSSH master connection per server, and later runs reuse it. A
check every 5 minutes therefore produces one login on the server, not one per
run. It also skips the key exchange each time. The tunnel method then leaves
nothing in the server's auth log per run. The memfile method still logs one
`sudo` session per run if `sudo: true`. `kea-lease-audit --close-ssh` closes the
masters.

The sockets live in `$XDG_RUNTIME_DIR/kea-lease-audit`. Service accounts usually
have no `$XDG_RUNTIME_DIR`, so the fallback is `~/.ssh/kea-lease-audit`. Unix
sockets have a path limit, so a long `control_dir` is rejected with an error.

### CheckMK

Install the tool on the monitoring server, or any host whose CheckMK agent can
reach the Kea servers over SSH. Then add local checks. CheckMK runs scripts
under `local/<seconds>/` asynchronously at that interval and caches the result:

    # /usr/lib/check_mk_agent/local/kea_ha              (every agent poll, ~1 min)
    #!/bin/sh
    exec kea-lease-audit -c /etc/kea-lease-audit/servers.yaml --check ha -o checkmk

    # /usr/lib/check_mk_agent/local/300/kea_leases      (every 5 min)
    #!/bin/sh
    exec kea-lease-audit -c /etc/kea-lease-audit/servers.yaml -o checkmk

The agent runs as root, so the key, `known_hosts_file` and control sockets are
root's.

### LibreNMS / Nagios / Icinga

Put a wrapper in the plugin directory (LibreNMS: `/usr/lib/nagios/plugins`,
files named `check_*`):

    # /usr/lib/nagios/plugins/check_kea_leases
    #!/bin/sh
    exec kea-lease-audit -c /etc/kea-lease-audit/servers.yaml -o nagios "$@"

Add it as a service with parameters such as `-r prod` or `--check ha`.
LibreNMS polls services every 5 minutes, which suits the lease check. When
drift triggers a recheck, a run takes at least `recheck_delay` (15s) longer.
Keep the plugin timeout comfortably above that.

## Discrepancy kinds

* **missing**: a live lease on some servers is absent (or expired/released) on others
* **stale**: same client, but `cltt`/`valid_lft` differ, so one peer missed a renewal
* **mismatch**: other fields differ (hwaddr, client-id/DUID, subnet, hostname, state…)

## Tests

    python3 -m unittest -v

## Releasing

Push a version tag from `main`:

    git tag v0.2.0
    git push origin v0.2.0

The Release workflow runs the tests, then builds the wheel, sdist and `.pyz`. It
smoke-tests the `.pyz`, then publishes a GitHub release with generated notes and
`SHA256SUMS`. The package version comes from the tag (setuptools-scm), so nothing
needs to be edited before tagging.

## License

MIT. See [LICENSE](LICENSE).
