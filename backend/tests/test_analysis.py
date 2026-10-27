import unittest

from analysis import extract_security_signals, severity_for


class SecuritySignalTests(unittest.TestCase):
    def test_detects_sender_mismatch_and_ip_url(self):
        content = """From: Billing <billing@trusted-bank.example>
Reply-To: verify@untrusted.example
Subject: Urgent action required

Verify your account at http://192.0.2.10/login now and provide your password.
"""
        result = extract_security_signals(content)
        titles = {signal["title"] for signal in result["signals"]}
        self.assertIn("Sender and reply-to domains differ", titles)
        self.assertIn("URL uses a direct IP address", titles)
        self.assertGreater(result["deterministic_score"], 25)

    def test_score_severity_bands(self):
        self.assertEqual(severity_for(20), "low")
        self.assertEqual(severity_for(35), "medium")
        self.assertEqual(severity_for(65), "high")
        self.assertEqual(severity_for(85), "critical")


if __name__ == "__main__":
    unittest.main()
