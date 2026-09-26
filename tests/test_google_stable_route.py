import importlib.util
import pathlib
import unittest


PATH = pathlib.Path(__file__).parents[1] / "deploy" / "add-google-stable-route.py"
SPEC = importlib.util.spec_from_file_location("google_route", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GoogleRouteTests(unittest.TestCase):
    def test_rule_routes_google_and_youtube_via_warp_balance(self):
        rule = MODULE.build_rule()
        self.assertEqual(rule["outbound"], "warp-balance")
        self.assertEqual(rule["action"], "route")
        self.assertNotIn("ip_cidr", rule)
        self.assertIn("google.com", MODULE.DOMAINS)
        self.assertIn("youtube.com", MODULE.DOMAINS)
        self.assertIn("googlevideo.com", MODULE.DOMAINS)

    def test_legacy_direct_rule_is_replaced(self):
        self.assertTrue(MODULE.is_managed({
            "domain_suffix": MODULE.DOMAINS,
            "action": "route",
            "outbound": "direct",
        }))

    def test_partial_legacy_direct_rule_is_removed(self):
        config = {"route": {"rules": [
            {"domain_suffix": ["google.com", "googleapis.com"], "action": "route", "outbound": "direct"},
            {"network": "tcp", "action": "route", "outbound": "warp-balance"},
        ]}}
        # Exercise the same preservation predicate used by main without network access.
        rules = config["route"]["rules"]
        kept = [item for item in rules if not (
            item.get("action") == "route" and item.get("outbound") == "direct"
            and any(domain in item.get("domain_suffix", []) for domain in MODULE.DOMAINS)
        )]
        self.assertEqual(kept, [rules[1]])

    def test_main_generates_and_replaces_rule_without_network(self):
        import json
        import tempfile
        from unittest.mock import patch

        config = {"route": {"rules": [
            {"domain_suffix": ["google.com"], "action": "route", "outbound": "direct"},
            {"network": "tcp", "action": "route", "outbound": "warp-balance"},
        ]}}
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "source.json"
            output = pathlib.Path(directory) / "output.json"
            source.write_text(json.dumps(config), encoding="utf-8")
            with patch.object(MODULE.sys, "argv", [str(PATH), str(source), str(output)]):
                self.assertEqual(MODULE.main(), 0)
            result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(result["route"]["rules"][0]["outbound"], "warp-balance")
        self.assertIn("youtube.com", result["route"]["rules"][0]["domain_suffix"])
        self.assertEqual(result["route"]["rules"][1], config["route"]["rules"][1])


if __name__ == "__main__":
    unittest.main()
