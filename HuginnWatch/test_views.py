from unittest.mock import patch
from django.test import TestCase
from HuginnWatch.views import analyze_vulnerabilities

class VulnerabilityScanTests(TestCase):

    @patch("HuginnWatch.views.requests.get")
    def test_analyze_vulnerabilities_with_cves(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2023-0001",
                        "descriptions": [{"lang": "en", "value": "Example vulnerability"}]
                    }
                }
            ]
        }
        ports_text = "22/tcp open ssh OpenSSH 7.4"
        result = analyze_vulnerabilities(ports_text)
        self.assertIn("CVE-2023-0001", result)
        self.assertIn("Vulnerabilities found", result)

    def test_analyze_vulnerabilities_no_ports(self):
        result = analyze_vulnerabilities("No open TCP ports found.")
        self.assertIn("No CVEs found", result)
