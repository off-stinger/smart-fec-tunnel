import importlib.util
import pathlib
import unittest


PATH = pathlib.Path(__file__).parents[1] / "deploy" / "sing-box-merge.py"
MODULE_SPEC = importlib.util.spec_from_file_location("sing_box_merge", PATH)
MODULE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(MODULE)


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.base = {
            "inbounds": [{"type": "vless", "tag": "reality", "listen_port": 443}],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"rules": [{"ip_is_private": True, "outbound": "direct"}]},
        }
        self.spec = {
            "inbounds": [{"type": "tuic", "tag": "tuic-inner"}],
            "outbounds": [{"type": "socks", "tag": "warp-balance"}],
            "endpoints": [{"type": "wireguard", "tag": "warp-a", "private_key": "secret"}],
            "route_rules": [{"network": "tcp", "outbound": "warp-balance"}],
            "route_position": "last",
            "route_final": "warp-a",
        }

    def test_preserves_existing_and_is_idempotent(self):
        first = MODULE.merge(self.base, self.spec)
        second = MODULE.merge(first, self.spec)
        self.assertEqual(first, second)
        self.assertEqual(first["inbounds"][0]["tag"], "reality")
        self.assertEqual(first["route"]["rules"][0]["outbound"], "direct")
        self.assertEqual(first["route"]["final"], "warp-a")

    def test_replaces_managed_object(self):
        old = MODULE.merge(self.base, self.spec)
        changed = dict(self.spec)
        changed["inbounds"] = [{"type": "tuic", "tag": "tuic-inner", "listen_port": 4443}]
        result = MODULE.merge(old, changed)
        matches = [x for x in result["inbounds"] if x["tag"] == "tuic-inner"]
        self.assertEqual(matches, changed["inbounds"])

    def test_rejects_duplicate_tags(self):
        self.spec["inbounds"].append({"type": "mixed", "tag": "tuic-inner"})
        with self.assertRaises(ValueError):
            MODULE.merge(self.base, self.spec)

    def test_rejects_duplicate_wireguard_identities(self):
        self.spec["endpoints"].append(
            {"type": "wireguard", "tag": "warp-b", "private_key": "secret"}
        )
        with self.assertRaisesRegex(ValueError, "independent private keys"):
            MODULE.merge(self.base, self.spec)


if __name__ == "__main__":
    unittest.main()
