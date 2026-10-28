import base64
import unittest
from unittest.mock import patch

from aiohttp import web

from antivirus_service.handler import ScanFileHandler
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
    async def test_index_requires_authentication(self):
        server = Webserver.__new__(Webserver)
        server.auth_keys = [base64.b64encode(b"user:password").decode("ascii")]

        with self.assertRaises(web.HTTPForbidden):
            server.index(FakeRequestWithoutAuth())

    async def test_internal_exception_details_are_not_returned(self):
        server = Webserver.__new__(Webserver)
        server.auth_keys = [base64.b64encode(b"user:password").decode("ascii")]
        server.download_allowed_origins = ["https://example.test"]
        server.callback_allowed_origins = ["https://example.test"]

        with self.assertLogs(level="ERROR"):
            with patch.object(
                server,
                "enqueue_scan_file_request",
                side_effect=RuntimeError("broker password: do-not-disclose"),
            ):
                response = await server.handle_file(FakeRequest())

        self.assertEqual(response.status, 500)
        self.assertEqual(response.text, "Internal Server Error")
        self.assertNotIn("do-not-disclose", response.text)

    async def test_unlisted_url_is_rejected_before_enqueue(self):
        server = Webserver.__new__(Webserver)
        server.auth_keys = [base64.b64encode(b"user:password").decode("ascii")]
        server.download_allowed_origins = ["https://example.test"]
        server.callback_allowed_origins = ["https://example.test"]

        with patch.object(server, "enqueue_scan_file_request") as enqueue:
            response = await server.handle_file(
                FakeRequestWithBody(
                    b'{"download_uri":"http://127.0.0.1/admin",'
                    b'"callback_uri":"https://example.test/callback"}'
                )
            )

        self.assertEqual(response.status, 422)
        enqueue.assert_not_called()


class FakeRequestWithBody(FakeRequest):
    def __init__(self, body):
        self.body = body

    async def read(self):
        return self.body


class FakeRequestWithoutAuth:
    headers = {}


class WorkerInputTests(unittest.TestCase):
    def test_worker_rejects_unlisted_callback_before_processing(self):
        handler = ScanFileHandler.__new__(ScanFileHandler)
        handler.download_allowed_origins = ["http://file-storage-svc:4444"]
        handler.callback_allowed_origins = ["http://file-storage-svc:4444"]
        body = (
            b'{"download_uri":"http://file-storage-svc:4444/api/v3/file-security/download/token",'
            b'"callback_uri":"http://127.0.0.1/admin"}'
        )

        with self.assertRaisesRegex(ValueError, "origin is not allowed"):
            handler.parse_body(body)


if __name__ == "__main__":
    unittest.main()
