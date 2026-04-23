import json
import tempfile
import unittest
from pathlib import Path

from src.intelligence.vector_store import VectorStore


class VectorStoreTests(unittest.TestCase):
    def test_query_raises_on_dimension_mismatch(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = VectorStore(Path(tmpdir) / "vectors.json")
            store.upsert("pat-1", [1.0, 0.0], {"root_cause": "NORMAL_CALL"})

            with self.assertRaisesRegex(ValueError, "dimension mismatch"):
                store.query([1.0, 0.0, 0.0])

    def test_mixed_dimension_store_is_rejected_on_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "vectors.json"
            path.write_text(
                json.dumps(
                    [
                        {"id": "pat-1", "vector": [1.0, 0.0]},
                        {"id": "pat-2", "vector": [0.0, 1.0, 0.0]},
                    ]
                ),
                encoding="utf-8",
            )

            store = VectorStore(path)
            self.assertEqual(store.items(), [])


if __name__ == "__main__":
    unittest.main()
