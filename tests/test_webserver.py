import base64
import unittest
from unittest.mock import patch

from antivirus_service.webserver import Webserver


class FakeRequest:
    headers = {
        "Authorization": "Basic "
        + base64.b64encode(b"user:password").decode("ascii")
    }

    async def read(self):
        return (
            b'{"download_uri":"https://example.test/file",'
            b'"callback_uri":"https://example.test/callback"}'
        )


class HandleFileTests(unittest.IsolatedAsyncioTestCase):
    async def test_internal_exception_details_are_not_returned(self):
        server = Webserver.__new__(Webserver)
        server.auth_keys = [base64.b64encode(b"user:password").decode("ascii")]

        with patch.object(
            server,
            "enqueue_scan_file_request",
            side_effect=RuntimeError("broker password: do-not-disclose"),
        ):
            response = await server.handle_file(FakeRequest())

        self.assertEqual(response.status, 500)
        self.assertEqual(response.text, "Internal Server Error")
        self.assertNotIn("do-not-disclose", response.text)


if __name__ == "__main__":
    unittest.main()
