import unittest
from unittest.mock import MagicMock, patch

import main


class MainLauncherTests(unittest.TestCase):
    def test_run_server_uses_waitress_when_not_debug(self):
        app = MagicMock()
        with patch("main.waitress_serve") as mocked_waitress:
            main.run_server(app, host="0.0.0.0", port=5050, debug=False)

        mocked_waitress.assert_called_once_with(app, host="0.0.0.0", port=5050)
        app.run.assert_not_called()

    def test_run_server_keeps_flask_debug_server_for_debug_mode(self):
        app = MagicMock()
        with patch("main.waitress_serve") as mocked_waitress:
            main.run_server(app, host="127.0.0.1", port=5051, debug=True)

        app.run.assert_called_once_with(host="127.0.0.1", port=5051, debug=True)
        mocked_waitress.assert_not_called()


if __name__ == "__main__":
    unittest.main()
