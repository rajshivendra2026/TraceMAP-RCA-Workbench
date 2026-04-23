import os
import unittest

from werkzeug.test import EnvironBuilder

from src.app.factory import create_app


class AppAuthTests(unittest.TestCase):
    def setUp(self):
        self._old_token = os.environ.get("TC_RCA__AUTH__TOKEN")

    def tearDown(self):
        if self._old_token is None:
            os.environ.pop("TC_RCA__AUTH__TOKEN", None)
        else:
            os.environ["TC_RCA__AUTH__TOKEN"] = self._old_token

    def test_learning_status_requires_token_when_configured(self):
        os.environ["TC_RCA__AUTH__TOKEN"] = "secret-token"
        app = create_app()

        response = self._dispatch(app, "/api/learning/status")
        self.assertEqual(response.status_code, 401)

        authorized = self._dispatch(
            app,
            "/api/learning/status",
            headers={"Authorization": "Bearer secret-token"},
        )
        self.assertEqual(authorized.status_code, 200)

    def test_health_endpoint_remains_open_with_auth_enabled(self):
        os.environ["TC_RCA__AUTH__TOKEN"] = "secret-token"
        app = create_app()

        response = self._dispatch(app, "/health")
        self.assertEqual(response.status_code, 200)

    def test_system_health_endpoint_remains_open_with_auth_enabled(self):
        os.environ["TC_RCA__AUTH__TOKEN"] = "secret-token"
        app = create_app()

        response = self._dispatch(app, "/api/system-health")
        self.assertEqual(response.status_code, 200)

    def _dispatch(self, app, path, *, method="GET", headers=None):
        builder = EnvironBuilder(path=path, method=method, headers=headers or {})
        with app.request_context(builder.get_environ()):
            return app.full_dispatch_request()


if __name__ == "__main__":
    unittest.main()
