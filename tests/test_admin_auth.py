import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from starlette.requests import Request

from app.api.v1 import admin
from app.core import auth


def _make_request() -> Request:
    return Request({"type": "http", "headers": []})


def _make_request_with_headers(headers: list[tuple[bytes, bytes]]) -> Request:
    return Request({"type": "http", "headers": headers})


class AdminAuthTests(unittest.IsolatedAsyncioTestCase):
    async def test_verify_admin_api_key_accepts_admin_password_when_user_keys_exist(self):
        async def fake_load_legacy_keys():
            return {"sk-user-key"}

        def fake_get_config(key, default=""):
            values = {
                "app.app_key": "secret-admin",
                "app.api_key": "",
            }
            return values.get(key, default)

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="secret-admin")

        with (
            patch.object(auth, "get_config", side_effect=fake_get_config),
            patch.object(auth, "_load_legacy_api_keys", new=fake_load_legacy_keys),
        ):
            token = await auth.verify_admin_api_key(_make_request(), creds)

        self.assertEqual(token, "secret-admin")

    async def test_verify_api_key_still_rejects_admin_password(self):
        async def fake_load_legacy_keys():
            return {"sk-user-key"}

        def fake_get_config(key, default=""):
            values = {
                "app.app_key": "secret-admin",
                "app.api_key": "",
            }
            return values.get(key, default)

        creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="secret-admin")

        with (
            patch.object(auth, "get_config", side_effect=fake_get_config),
            patch.object(auth, "_load_legacy_api_keys", new=fake_load_legacy_keys),
        ):
            with self.assertRaises(HTTPException):
                await auth.verify_api_key(_make_request(), creds)

    async def test_verify_admin_api_key_accepts_x_admin_key_header(self):
        async def fake_load_legacy_keys():
            return set()

        def fake_get_config(key, default=""):
            values = {
                "app.app_key": "secret-admin",
                "app.api_key": "",
            }
            return values.get(key, default)

        request = _make_request_with_headers([(b"x-admin-key", b"secret-admin")])

        with (
            patch.object(auth, "get_config", side_effect=fake_get_config),
            patch.object(auth, "_load_legacy_api_keys", new=fake_load_legacy_keys),
        ):
            token = await auth.verify_admin_api_key(request)

        self.assertEqual(token, "secret-admin")

    async def test_verify_api_key_accepts_x_api_key_header(self):
        async def fake_load_legacy_keys():
            return set()

        def fake_get_config(key, default=""):
            values = {
                "app.app_key": "secret-admin",
                "app.api_key": "service-key",
            }
            return values.get(key, default)

        request = _make_request_with_headers([(b"x-api-key", b"service-key")])

        with (
            patch.object(auth, "get_config", side_effect=fake_get_config),
            patch.object(auth, "_load_legacy_api_keys", new=fake_load_legacy_keys),
        ):
            token = await auth.verify_api_key(request)

        self.assertEqual(token, "service-key")

    async def test_admin_login_returns_admin_password_as_admin_token(self):
        def fake_get_config(key, default=""):
            values = {
                "app.admin_username": "admin",
                "app.app_key": "secret-admin",
                "app.api_key": "",
            }
            return values.get(key, default)

        with patch.object(admin, "get_config", side_effect=fake_get_config):
            result = await admin.admin_login_api(
                _make_request(),
                admin.AdminLoginBody(username="admin", password="secret-admin"),
            )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["api_key"], "secret-admin")
        self.assertEqual(result["service_api_key"], "")
