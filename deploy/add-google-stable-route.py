#!/usr/bin/env python3
"""Add an idempotent WARP route for Google web properties."""

import json
import sys


DOMAINS = [
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "ggpht.com",
    "youtube.com",
    "youtube-nocookie.com",
    "googlevideo.com",
    "ytimg.com",
    "youtubei.googleapis.com",
]
def build_rule():
    return {
        "domain_suffix": DOMAINS,
        "action": "route",
        "outbound": "warp-balance",
    }


def is_managed(item):
    return (
        item.get("domain_suffix") == DOMAINS
        and item.get("action") == "route"
        and item.get("outbound") in ("direct", "warp-balance")
    )


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.json> <output.json>", file=sys.stderr)
        return 2
    with open(sys.argv[1], encoding="utf-8") as handle:
        config = json.load(handle)
    route = config.setdefault("route", {})
    rules = route.setdefault("rules", [])
    rules[:] = [
        item for item in rules
        if not is_managed(item)
        and not (
            isinstance(item, dict)
            and item.get("action") == "route"
            and item.get("outbound") == "direct"
            and any(domain in item.get("domain_suffix", []) for domain in DOMAINS)
        )
    ]
    position = next(
        (
            index for index, item in enumerate(rules)
            if isinstance(item, dict) and item.get("network") in ("tcp", ["tcp"])
        ),
        len(rules),
    )
    rules.insert(position, build_rule())
    with open(sys.argv[2], "w", encoding="utf-8") as handle:
        json.dump(config, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
