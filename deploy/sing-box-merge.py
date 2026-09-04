#!/usr/bin/env python3
"""Idempotently merge Smart FEC managed objects into a sing-box config."""

import argparse
import copy
import json
import sys


def fail(message):
    raise ValueError(message)


def tagged(items, label):
    if not isinstance(items, list):
        fail(f"{label} must be an array")
    tags = []
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("tag"), str):
            fail(f"every {label} item must have a string tag")
        tags.append(item["tag"])
    if len(tags) != len(set(tags)):
        fail(f"duplicate tag in {label}")
    return tags


def upsert(existing, additions, managed_tags):
    kept = [item for item in existing if item.get("tag") not in managed_tags]
    return kept + copy.deepcopy(additions)


def validate_wireguard_identities(endpoints):
    identities = []
    for endpoint in endpoints:
        if endpoint.get("type") != "wireguard":
            continue
        private_key = endpoint.get("private_key")
        if not isinstance(private_key, str) or not private_key.strip():
            fail(f"wireguard endpoint {endpoint['tag']} requires a private_key")
        identities.append(private_key)
    if len(identities) != len(set(identities)):
        fail("wireguard endpoints must use independent private keys")


def merge(base, spec):
    if not isinstance(base, dict) or not isinstance(spec, dict):
        fail("base and deployment spec must be JSON objects")

    inbounds = spec.get("inbounds", [])
    outbounds = spec.get("outbounds", [])
    endpoints = spec.get("endpoints", [])
    inbound_tags = tagged(inbounds, "inbounds")
    outbound_tags = tagged(outbounds, "outbounds")
    endpoint_tags = tagged(endpoints, "endpoints")
    validate_wireguard_identities(endpoints)
    all_tags = inbound_tags + outbound_tags + endpoint_tags
    if len(all_tags) != len(set(all_tags)):
        fail("managed tags must be unique across inbounds, outbounds and endpoints")

    routes = spec.get("route_rules", [])
    if not isinstance(routes, list) or not all(isinstance(x, dict) for x in routes):
        fail("route_rules must be an array of objects")

    result = copy.deepcopy(base)
    for key, values, tags in (
        ("inbounds", inbounds, set(inbound_tags)),
        ("outbounds", outbounds, set(outbound_tags)),
        ("endpoints", endpoints, set(endpoint_tags)),
    ):
        current = result.get(key, [])
        if not isinstance(current, list):
            fail(f"base {key} must be an array")
        result[key] = upsert(current, values, tags)

    route = result.setdefault("route", {})
    if not isinstance(route, dict):
        fail("base route must be an object")
    old_rules = route.get("rules", [])
    if not isinstance(old_rules, list):
        fail("base route.rules must be an array")

    # Remove only rules that are byte-for-byte equal to rules managed by this spec.
    # This preserves user policy and makes repeated deployments idempotent.
    old_rules = [rule for rule in old_rules if rule not in routes]
    position = spec.get("route_position", "first")
    if position == "first":
        route["rules"] = copy.deepcopy(routes) + old_rules
    elif position == "last":
        route["rules"] = old_rules + copy.deepcopy(routes)
    else:
        fail("route_position must be first or last")

    if "route_final" in spec:
        route["final"] = spec["route_final"]
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--spec", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        with open(args.base, encoding="utf-8") as handle:
            base = json.load(handle)
        with open(args.spec, encoding="utf-8") as handle:
            spec = json.load(handle)
        result = merge(base, spec)
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(result, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"sing-box merge failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
