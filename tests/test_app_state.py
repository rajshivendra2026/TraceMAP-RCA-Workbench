import sys
import tempfile
import types
import unittest
import importlib.util
from pathlib import Path
from unittest.mock import patch


sys.modules.setdefault("yaml", types.SimpleNamespace(safe_load=lambda _: {}))
STATE_PATH = Path("/Users/shivendraraj/Downloads/Tool-2/src/app/state.py")
spec = importlib.util.spec_from_file_location("test_state_module", STATE_PATH)
state = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(state)


class AppStateTests(unittest.TestCase):
    def test_fail_incomplete_jobs_marks_running_jobs_failed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = Path(tmpdir) / "jobs.sqlite"

            with patch.object(state, "_job_store_path", return_value=db_path):
                job = state.create_job("upload", message="Queued upload", progress=5)
                state.update_job(job["job_id"], status="running", message="Correlating sessions", progress=45)

                updated = state.fail_incomplete_jobs("Job interrupted by app restart")
                recovered = state.get_job(job["job_id"])

        self.assertEqual(updated, 1)
        self.assertEqual(recovered["status"], "failed")
        self.assertEqual(recovered["message"], "Job interrupted by app restart")
        self.assertEqual(recovered["error"], "Job interrupted by app restart")


if __name__ == "__main__":
    unittest.main()
