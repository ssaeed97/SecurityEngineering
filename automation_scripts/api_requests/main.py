"""
THREAT INTEL API CLIENT — API Calls with requests + Unit Tests
Security Engineer Coding Practice Problem #9

=====================================================================
REFERENCE NOTES — requests, Error Handling, unittest, Mocking
=====================================================================

WHY THIS MATTERS FOR SE WORK:
-------------------------------
  - Security tools constantly call APIs: threat intel feeds, SIEM APIs,
    vulnerability scanners, cloud provider APIs, SOAR playbooks
  - Knowing how to make reliable API calls with proper error handling
    is a core SE skill
  - Writing tests with mocks proves you can build reliable tooling
    that doesn't break when external services are unavailable


requests LIBRARY — MAKING API CALLS:
---------------------------------------
  import requests

  # GET request with query parameters and timeout
  response = requests.get(
      "https://api.example.com/check",
      params={"ip": "8.8.8.8"},    # becomes ?ip=8.8.8.8
      timeout=5                     # give up after 5 seconds
  )

  # What you get back:
  response.status_code   → 200, 404, 429, 500, etc.
  response.json()        → response body parsed as Python dict
  response.text          → raw text response
  response.headers       → response headers as dict


FIVE THINGS THAT CAN GO WRONG:
---------------------------------
  1. Success (200)         → parse and return data
  2. Rate limited (429)    → back off, retry later
  3. Server error (500)    → API is broken, return error status
  4. Timeout               → API didn't respond in time
  5. Connection failure    → API is unreachable (DNS, network, etc.)

  Your function must handle ALL five gracefully — never crash.


.get() vs [] FOR DICT ACCESS:
-------------------------------
  data["malicious"]              → crashes with KeyError if missing
  data.get("malicious", False)   → returns False if missing, no crash

  ALWAYS use .get() when parsing API responses — you can't trust
  that external APIs will always return every field.


MOCKING — TESTING WITHOUT REAL API CALLS:
-------------------------------------------
  In tests, you NEVER call the real API. You mock it — replace
  requests.get with a fake that returns whatever you want.

  from unittest.mock import patch, Mock

  @patch("requests.get")           # intercept all calls to requests.get
  def test_something(self, mock_get):
      mock_response = Mock()
      mock_response.status_code = 200
      mock_response.json.return_value = {"key": "value"}
      mock_get.return_value = mock_response  # requests.get() returns this

  Two ways to control the mock:
    mock_get.return_value = something        → returns that value
    mock_get.side_effect = SomeException()   → raises that exception


unittest ASSERTIONS:
----------------------
  self.assertEqual(a, b)      → a must equal b
  self.assertTrue(x)          → x must be True
  self.assertFalse(x)         → x must be False
  self.assertIn(item, list)   → item must be in list
  self.assertIsNone(x)        → x must be None
  self.assertRaises(Error)    → code must raise that error


ONE-LINE RECALLS:
------------------
  requests:   "requests.get(url, params, timeout) — params become query
               string, timeout prevents hanging"
  Error handling: "try/except for Timeout and ConnectionError — handle
                   every failure mode, never crash"
  Mocking:    "@patch('requests.get') replaces real API with fake —
               return_value for responses, side_effect for exceptions"
  .get():     "dict.get(key, default) is safe — returns default instead
               of crashing on missing keys"

=====================================================================
"""

import requests
import unittest
from unittest.mock import patch, Mock


API_URL = "https://api.threatintel.example.com/v1/check"


def check_ip(ip, timeout=5):
    """
    Check a single IP against the threat intelligence API.

    Returns a dict with:
      - status: "success", "rate_limited", "timeout", "connection_error", or "error"
      - malicious: True/False (only when status is "success")
      - threat_type: string or None
      - confidence: float 0.0-1.0
    """
    try:
        response = requests.get(API_URL, params={"ip": ip}, timeout=timeout)

        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "malicious": data.get("malicious", False),
                "threat_type": data.get("threat_type"),
                "confidence": data.get("confidence", 0.0),
                "status": "success",
            }
        elif response.status_code == 429:
            return {"ip": ip, "status": "rate_limited"}
        else:
            return {"ip": ip, "status": "error", "code": response.status_code}

    except requests.exceptions.Timeout:
        return {"ip": ip, "status": "timeout"}
    except requests.exceptions.ConnectionError:
        return {"ip": ip, "status": "connection_error"}
    except Exception as e:
        return {"ip": ip, "status": "unknown_error", "detail": str(e)}


def check_multiple_ips(ip_list, timeout=5):
    """
    Check multiple IPs and return a categorized summary.

    Returns a dict with counts and details for malicious, clean, and error results.
    """
    results = []
    for ip in ip_list:
        results.append(check_ip(ip, timeout))

    malicious = [r for r in results if r.get("malicious")]
    clean = [r for r in results if r.get("status") == "success" and not r.get("malicious")]
    errors = [r for r in results if r.get("status") != "success"]

    return {
        "total": len(results),
        "malicious_count": len(malicious),
        "clean_count": len(clean),
        "error_count": len(errors),
        "malicious_ips": malicious,
        "errors": errors,
        "all_results": results,
    }


# =====================================================================
# UNIT TESTS — Run with: python -m unittest main.py -v
# =====================================================================

class TestCheckIP(unittest.TestCase):
    """Tests for the check_ip function."""

    @patch("requests.get")
    def test_malicious_ip(self, mock_get):
        """Malicious IP should return status=success, malicious=True."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "203.45.167.22",
            "malicious": True,
            "threat_type": "botnet",
            "confidence": 0.95,
        }
        mock_get.return_value = mock_response

        result = check_ip("203.45.167.22")

        self.assertEqual(result["status"], "success")
        self.assertTrue(result["malicious"])
        self.assertEqual(result["threat_type"], "botnet")
        self.assertEqual(result["confidence"], 0.95)

    @patch("requests.get")
    def test_clean_ip(self, mock_get):
        """Clean IP should return status=success, malicious=False."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "8.8.8.8",
            "malicious": False,
            "threat_type": None,
            "confidence": 0.0,
        }
        mock_get.return_value = mock_response

        result = check_ip("8.8.8.8")

        self.assertEqual(result["status"], "success")
        self.assertFalse(result["malicious"])
        self.assertIsNone(result["threat_type"])

    @patch("requests.get")
    def test_rate_limited(self, mock_get):
        """429 response should return status=rate_limited."""
        mock_response = Mock()
        mock_response.status_code = 429
        mock_get.return_value = mock_response

        result = check_ip("1.2.3.4")

        self.assertEqual(result["status"], "rate_limited")

    @patch("requests.get")
    def test_server_error(self, mock_get):
        """500 response should return status=error with code."""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = check_ip("1.2.3.4")

        self.assertEqual(result["status"], "error")
        self.assertEqual(result["code"], 500)

    @patch("requests.get")
    def test_timeout(self, mock_get):
        """Timeout should return status=timeout, not crash."""
        mock_get.side_effect = requests.exceptions.Timeout()

        result = check_ip("1.2.3.4")

        self.assertEqual(result["status"], "timeout")

    @patch("requests.get")
    def test_connection_error(self, mock_get):
        """Connection failure should return status=connection_error."""
        mock_get.side_effect = requests.exceptions.ConnectionError()

        result = check_ip("1.2.3.4")

        self.assertEqual(result["status"], "connection_error")

    @patch("requests.get")
    def test_missing_fields_in_response(self, mock_get):
        """API response missing fields should use defaults, not crash."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ip": "5.5.5.5",
            # missing malicious, threat_type, and confidence
        }
        mock_get.return_value = mock_response

        result = check_ip("5.5.5.5")

        self.assertEqual(result["status"], "success")
        self.assertFalse(result["malicious"])  # defaults to False
        self.assertEqual(result["confidence"], 0.0)  # defaults to 0.0


class TestCheckMultipleIPs(unittest.TestCase):
    """Tests for the check_multiple_ips function."""

    @patch("requests.get")
    def test_mixed_results(self, mock_get):
        """Batch check should correctly categorize mixed results."""

        def side_effect_func(*args, **kwargs):
            ip = kwargs.get("params", {}).get("ip", "")
            mock_resp = Mock()

            if ip == "203.45.167.22":
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "ip": ip, "malicious": True,
                    "threat_type": "botnet", "confidence": 0.95,
                }
            elif ip == "8.8.8.8":
                mock_resp.status_code = 200
                mock_resp.json.return_value = {
                    "ip": ip, "malicious": False,
                    "threat_type": None, "confidence": 0.0,
                }
            else:
                mock_resp.status_code = 500

            return mock_resp

        mock_get.side_effect = side_effect_func

        result = check_multiple_ips(["203.45.167.22", "8.8.8.8", "1.2.3.4"])

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["malicious_count"], 1)
        self.assertEqual(result["clean_count"], 1)
        self.assertEqual(result["error_count"], 1)


# =====================================================================
# DEMO — Run directly to see example output
# =====================================================================

if __name__ == "__main__":
    print("=== Running Unit Tests ===\n")
    # Run tests programmatically
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(__import__(__name__))
    runner = unittest.TextTestRunner(verbosity=2)
    test_result = runner.run(suite)

    print("\n" + "=" * 60)
    print("=== Demo: check_multiple_ips (will fail without real API) ===\n")

    demo_ips = ["203.45.167.22", "8.8.8.8", "1.2.3.4", "10.0.0.1"]
    results = check_multiple_ips(demo_ips, timeout=2)

    print(f"  Total checked: {results['total']}")
    print(f"  Malicious: {results['malicious_count']}")
    print(f"  Clean: {results['clean_count']}")
    print(f"  Errors: {results['error_count']}")

    if results["malicious_ips"]:
        print("\n  Malicious IPs:")
        for r in results["malicious_ips"]:
            print(f"    {r['ip']} — {r['threat_type']} (confidence: {r['confidence']})")

    if results["errors"]:
        print("\n  Errors:")
        for r in results["errors"]:
            print(f"    {r['ip']} — {r['status']}")