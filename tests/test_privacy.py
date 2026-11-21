import unittest

from asustor_nas_cli.privacy import host_fingerprint, redact_ip_addresses, redact_sensitive_text


class PrivacyTests(unittest.TestCase):
    def test_network_addresses_and_prefixes_are_redacted(self):
        result = redact_ip_addresses("inet 192.0.2.10/24 inet6 fe80::1/64 brd 192.0.2.255")
        self.assertNotIn("192.0.2.10", result)
        self.assertNotIn("fe80::1", result)
        self.assertIn("[redacted-ip]/24", result)
        self.assertIn("[redacted-ip]/64", result)

    def test_network_mac_addresses_are_redacted(self):
        result = redact_sensitive_text("link/ether 00:11:22:33:44:55", include_all_ips=True)
        self.assertNotIn("00:11:22:33:44:55", result)
        self.assertIn("[redacted-mac]", result)

    def test_host_and_account_are_redacted_from_error_text(self):
        result = redact_sensitive_text("ssh nas-user@nas.example failed", "nas.example", "nas-user")
        self.assertNotIn("nas-user", result)
        self.assertNotIn("nas.example", result)
        self.assertIn("[redacted-account]", result)
        self.assertIn("[redacted-host]", result)

    def test_host_fingerprint_is_stable_but_not_the_literal_address(self):
        value = host_fingerprint("192.0.2.10")
        self.assertEqual(value, host_fingerprint("192.0.2.10"))
        self.assertNotIn("192.0.2.10", value)


if __name__ == "__main__":
    unittest.main()
