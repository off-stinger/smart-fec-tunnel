import importlib.util
import pathlib
import unittest


PATH = pathlib.Path(__file__).parents[1] / "deploy" / "add-google-stable-route.py"
SPEC = importlib.util.spec_from_file_location("google_route", PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class GoogleRouteTests(unittest.TestCase):
    def test_rule_shape_and_domains(self):
        self.assertIn("google.com", MODULE.DOMAINS)
        self.assertNotIn("youtube.com", MODULE.DOMAINS)

    def test_subtracts_cloud_ranges(self):
        import ipaddress

        source = [ipaddress.ip_network("192.0.2.0/24")]
        excluded = [ipaddress.ip_network("192.0.2.0/25")]
        self.assertEqual(
            MODULE.subtract_networks(source, excluded),
            [ipaddress.ip_network("192.0.2.128/25")],
        )

    def test_handles_mixed_ip_versions(self):
        import ipaddress

        source = [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("2001:db8::/32")]
        self.assertEqual(MODULE.subtract_networks(source, []), source)


if __name__ == "__main__":
    unittest.main()
