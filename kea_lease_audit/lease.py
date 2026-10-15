"""Normalized lease record shared by all collectors."""

from dataclasses import dataclass, fields

# Kea lease states
STATE_DEFAULT = 0
STATE_DECLINED = 1
STATE_EXPIRED_RECLAIMED = 2
STATE_RELEASED = 3


@dataclass(frozen=True)
class Lease:
    family: int
    address: str
    lease_type: str      # V4, IA_NA, IA_TA, IA_PD
    prefix_len: int
    hwaddr: str
    client_id: str       # client-id (v4) or DUID (v6)
    iaid: object
    valid_lft: int
    cltt: int
    subnet_id: int
    fqdn_fwd: bool
    fqdn_rev: bool
    hostname: str
    state: int

    @property
    def key(self):
        return (self.address, self.lease_type, self.prefix_len)

    @property
    def expire(self):
        return self.cltt + self.valid_lft

    def is_live(self, now):
        """True if the lease is in use as of `now` (unexpired and not reclaimed/released)."""
        return self.state in (STATE_DEFAULT, STATE_DECLINED) and self.expire > now

    def to_dict(self):
        d = {f.name: getattr(self, f.name) for f in fields(self)}
        d["expire"] = self.expire
        return d


def from_api(family, item):
    """Build a Lease from a lease4-get*/lease6-get* API response element."""
    valid = int(item.get("valid-lft", 0))
    cltt = int(item.get("cltt", 0))
    common = dict(
        family=family,
        address=item["ip-address"],
        hwaddr=(item.get("hw-address") or "").lower(),
        valid_lft=valid,
        cltt=cltt,
        subnet_id=int(item.get("subnet-id", 0)),
        fqdn_fwd=bool(item.get("fqdn-fwd", False)),
        fqdn_rev=bool(item.get("fqdn-rev", False)),
        hostname=(item.get("hostname") or "").lower(),
        state=int(item.get("state", 0)),
    )
    if family == 4:
        return Lease(lease_type="V4", prefix_len=32, client_id=(item.get("client-id") or "").lower(),
                     iaid=None, **common)
    return Lease(lease_type=item.get("type", "IA_NA"), prefix_len=int(item.get("prefix-len", 128)),
                 client_id=(item.get("duid") or "").lower(), iaid=int(item.get("iaid", 0)), **common)
