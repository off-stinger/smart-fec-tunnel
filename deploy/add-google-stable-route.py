#!/usr/bin/env python3
"""Add an idempotent stable direct route for Google web properties."""

import json
import ipaddress
import sys
from urllib.request import urlopen


DOMAINS = [
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "ggpht.com",
]
RANGE_URLS = {
    "goog": "https://www.gstatic.com/ipranges/goog.json",
    "cloud": "https://www.gstatic.com/ipranges/cloud.json",
}


def load_networks(url):
    with urlopen(url, timeout=15) as response:
        data = json.load(response)
    return [
        ipaddress.ip_network(item.get("ipv4Prefix") or item.get("ipv6Prefix"))
        for item in data["prefixes"]
    ]


def subtract_networks(source, excluded):
    result = list(source)
    for removal in excluded:
        updated = []
        for network in result:
            if network.version != removal.version or not network.overlaps(removal):
                updated.append(network)
            elif removal.supernet_of(network) or removal == network:
                continue
            elif network.supernet_of(removal):
                updated.extend(network.address_exclude(removal))
            else:
                raise ValueError(f"unexpected partial CIDR overlap: {network}, {removal}")
        result = updated
    ipv4 = ipaddress.collapse_addresses(item for item in result if item.version == 4)
    ipv6 = ipaddress.collapse_addresses(item for item in result if item.version == 6)
    return list(ipv4) + list(ipv6)


def build_rule():
    google = load_networks(RANGE_URLS["goog"])
    cloud = load_networks(RANGE_URLS["cloud"])
    service_ranges = subtract_networks(google, cloud)
    return {
        "domain_suffix": DOMAINS,
        "ip_cidr": [str(item) for item in service_ranges],
        "action": "route",
        "outbound": "direct",
    }


def is_managed(item):
    return (
        item.get("domain_suffix") == DOMAINS
        and item.get("action") == "route"
        and item.get("outbound") == "direct"
    )


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as handle:
        config = json.load(handle)
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    rules[:] = [item for item in rules if not is_managed(item)]
    position = next(
        (index for index, item in enumerate(rules) if item.get("network") == "tcp"),
        len(rules),
    )
    rules.insert(position, build_rule())
    with open(sys.argv[2], "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
