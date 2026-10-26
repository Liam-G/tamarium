"""Ensure the distributable example and generic runner remain self-contained."""
import tempfile
import unittest
from pathlib import Path

import proofctl
from assurance import validate_policy


class ReleaseTests(unittest.TestCase):
    def test_every_model_has_an_independent_mutation_policy(self):
        import json
        policies = json.loads((proofctl.ROOT / "assurance.json").read_text())["models"]
        models = proofctl.load_manifest()
        self.assertEqual(set(policies), {model["id"] for model in models})
        for model in models:
            validate_policy(model, policies[model["id"]])

    def test_metadata_snapshot_contains_exactly_the_generic_inputs(self):
        expected = {"suite.json", "assurance.json", "toolchain.json", "proofctl.py",
                    "assurance.py", "tamarin_text.py", "workflows.py"}
        self.assertEqual(set(proofctl.INPUT_NAMES), expected)
        with tempfile.TemporaryDirectory() as directory:
            hashes = proofctl.snapshot_metadata(Path(directory))
            self.assertEqual(set(hashes), expected)
            self.assertTrue(all(len(digest) == 64 for digest in hashes.values()))


if __name__ == "__main__":
    unittest.main()
