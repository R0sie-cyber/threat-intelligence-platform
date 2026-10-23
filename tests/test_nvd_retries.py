
import unittest
from unittest.mock import Mock, patch

import requests

from src.enrichment.nvd_enrichment import fetch_nvd_data


class TestNVDRetries(unittest.TestCase):

    @patch("src.enrichment.nvd_enrichment.time.sleep")
    @patch("src.enrichment.nvd_enrichment.requests.get")
    def test_404_does_not_retry(self, mock_get, mock_sleep):
        response = Mock()
        response.status_code = 404
        response.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("404 Not Found")
        )

        mock_get.return_value = response

        with self.assertRaises(requests.exceptions.HTTPError):
            fetch_nvd_data("CVE-2026-16232")

        self.assertEqual(mock_get.call_count, 1)
        mock_sleep.assert_not_called()

    @patch("src.enrichment.nvd_enrichment.time.sleep")
    @patch("src.enrichment.nvd_enrichment.requests.get")
    def test_503_retries_then_succeeds(self, mock_get, mock_sleep):
        unavailable = Mock()
        unavailable.status_code = 503
        unavailable.headers = {}
        unavailable.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("503 Unavailable")
        )

        successful = Mock()
        successful.status_code = 200
        successful.json.return_value = {"vulnerabilities": []}

        mock_get.side_effect = [unavailable, successful]

        result = fetch_nvd_data("CVE-2026-16232")

        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(result, {"vulnerabilities": []})
        mock_sleep.assert_called_once()

    @patch("src.enrichment.nvd_enrichment.time.sleep")
    @patch("src.enrichment.nvd_enrichment.requests.get")
    def test_connection_error_retries(self, mock_get, mock_sleep):
        successful = Mock()
        successful.status_code = 200
        successful.json.return_value = {"vulnerabilities": []}

        mock_get.side_effect = [
            requests.exceptions.ConnectionError(
                "Temporary network failure"
            ),
            successful
        ]

        result = fetch_nvd_data("CVE-2026-16232")

        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(result, {"vulnerabilities": []})
        mock_sleep.assert_called_once()


if __name__ == "__main__":
    unittest.main()
