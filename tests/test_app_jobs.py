import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.test import EnvironBuilder

from src.app.factory import create_app
from src.app.state import update_job, update_learning_status


class _ImmediateThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None):
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self):
        if self._target:
            self._target(*self._args, **self._kwargs)


class AppJobTests(unittest.TestCase):
    def setUp(self):
        self._old_token = os.environ.get("TC_RCA__AUTH__TOKEN")
        self._tmpdir = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmpdir.cleanup)
        self.jobs_db = Path(self._tmpdir.name) / "jobs.sqlite"
        self.upload_dir = Path(self._tmpdir.name) / "raw_pcaps"
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        if self._old_token is None:
            os.environ.pop("TC_RCA__AUTH__TOKEN", None)
        else:
            os.environ["TC_RCA__AUTH__TOKEN"] = self._old_token

    def test_upload_returns_job_and_status_endpoint_hydrates_result(self):
        app = create_app()

        sessions = [{"call_id": "sess-1", "rca": {"rca_label": "NORMAL_CALL"}}]
        summarized_sessions = [{"call_id": "sess-1", "rca_label": "NORMAL_CALL"}]
        summary = {"details": {"trace_type": "test capture"}}

        with patch("src.app.state.cfg_path", return_value=str(self.jobs_db)), patch(
            "src.app.factory.build_upload_path", return_value=self.upload_dir / "trace-upload.pcap"
        ), patch("src.app.factory.Thread", _ImmediateThread), patch(
            "src.app.factory.load_pcap", return_value={"sip": [], "radius": []}
        ), patch("src.app.factory.build_sessions", return_value=sessions), patch(
            "src.app.factory.apply_rca", side_effect=lambda payload: payload
        ), patch("src.app.factory.apply_correlation", side_effect=lambda payload: payload), patch(
            "src.app.factory.run_learning_cycle",
            return_value={"sessions": sessions, "metrics": {"patterns_reused": 0}},
        ), patch("src.app.factory.build_capture_graph", return_value={"nodes": [], "edges": []}), patch(
            "src.app.factory.build_capture_summary", return_value=summary
        ), patch("src.app.factory.session_summary", side_effect=summarized_sessions):
            response = self._dispatch(
                app,
                "/upload",
                method="POST",
                data={"file": (io.BytesIO(b"pcap"), "trace.pcap")},
            )
            self.assertEqual(response.status_code, 202)
            payload = response.get_json()
            self.assertTrue(payload["accepted"])
            self.assertIn("job_id", payload)

            status = self._dispatch(app, f"/api/upload-status/{payload['job_id']}")
            self.assertEqual(status.status_code, 200)
            job = status.get_json()
            self.assertEqual(job["status"], "completed")
            self.assertEqual(job["result"]["summary"], summary)
            self.assertEqual(job["result"]["sessions"], summarized_sessions)

    def test_learning_start_returns_job_and_generic_status_endpoint(self):
        app = create_app()
        trace_path = self.upload_dir / "batch-trace.pcap"
        trace_path.write_bytes(b"pcap")

        def fake_learning_job(path, pending, job_id):
            update_job(
                job_id,
                status="completed",
                message="Learning complete. Processed 1 new PCAP(s).",
                progress=100,
                processed_pcaps=1,
                total_pcaps=1,
                result={"processed_pcaps": 1, "path": path},
            )
            update_learning_status(
                running=False,
                message="Learning complete. Processed 1 new PCAP(s).",
                path=path,
                processed_pcaps=1,
                new_pcaps=1,
                last_result={"processed_pcaps": 1, "path": path},
                learning_job_id=job_id,
            )

        with patch("src.app.state.cfg_path", return_value=str(self.jobs_db)), patch(
            "src.app.factory.Thread", _ImmediateThread
        ), patch(
            "src.app.factory.discover_pcaps",
            return_value=[
                {
                    "path": str(trace_path),
                    "name": trace_path.name,
                    "signature": "sig-1",
                    "size": trace_path.stat().st_size,
                    "mtime": int(trace_path.stat().st_mtime),
                }
            ],
        ), patch("src.app.factory.load_learning_manifest", return_value={}), patch(
            "src.app.factory.run_learning_job", side_effect=fake_learning_job
        ):
            response = self._dispatch(
                app,
                "/api/learning/start",
                method="POST",
                headers={"Content-Type": "application/json"},
                data='{"path": "%s"}' % self.upload_dir,
            )
            self.assertEqual(response.status_code, 200)
            payload = response.get_json()
            self.assertTrue(payload["started"])
            self.assertIn("job_id", payload)

            status = self._dispatch(app, f"/api/job-status/{payload['job_id']}")
            self.assertEqual(status.status_code, 200)
            job = status.get_json()
            self.assertEqual(job["kind"], "learning")
            self.assertEqual(job["status"], "completed")
            self.assertEqual(job["result"]["processed_pcaps"], 1)

    def _dispatch(self, app, path, *, method="GET", headers=None, data=None):
        builder = EnvironBuilder(path=path, method=method, headers=headers or {}, data=data)
        with app.request_context(builder.get_environ()):
            return app.full_dispatch_request()


if __name__ == "__main__":
    unittest.main()
