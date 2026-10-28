import unittest

from antivirus_service.url_validation import validate_url


class ValidateUrlTests(unittest.TestCase):
    def test_allows_presigned_url_on_allowlisted_origin(self):
        url = "https://s3.example.test/bucket/object?signature=secret"

        self.assertEqual(
            validate_url(url, ["https://s3.example.test"]),
            url,
        )

    def test_rejects_unlisted_origin(self):
        with self.assertRaisesRegex(ValueError, "origin is not allowed"):
            validate_url("http://127.0.0.1/admin", ["http://file-storage-svc:4444"])

    def test_rejects_userinfo_even_on_an_allowed_host(self):
        with self.assertRaisesRegex(ValueError, r"absolute HTTP\(S\) URL"):
            validate_url("https://user:password@s3.example.test/object", ["https://s3.example.test"])
