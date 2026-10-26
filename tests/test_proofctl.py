"""Exercise the boundary between a completed proof and a failed process."""
from __future__ import annotations

import tempfile
from pathlib import Path
import json
import os
import sys
import unittest
from unittest.mock import patch

import proofctl


def summary(*rows: str) -> str:
    return "summary of summaries:\nanalyzed: sample.spthy\n\n" + "\n".join("  " + row for row in rows)


class ContractTests(unittest.TestCase):
    def test_reference_accepts_negative_reachability_but_rejects_failed_safety(self):
        source = '''lemma executable: exists-trace "Ex #i. Good()@i"
lemma forbidden [use_induction]: exists-trace "Ex #i. Bad()@i"
lemma security: "All #i. Bad()@i ==> F"'''
        case = {"defines": [], "expect": {"executable": "verified", "forbidden": "falsified", "security": "verified"}}
        proofctl.validate_reference(case, source)
        for change in ({"defines": ["WEAKEN"]},
                       {"expect": dict(case["expect"], security="falsified")},
                       {"expect": dict(case["expect"], missing="falsified")}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                proofctl.validate_reference(dict(case, **change), source)

    def test_commented_exists_trace_cannot_mask_failed_reference_safety(self):
        source = '''// lemma security: exists-trace
lemma security /* exists-trace */: "All #i. Bad()@i ==> F"'''
        with self.assertRaises(ValueError):
            proofctl.validate_reference({"defines": [], "expect": {"security": "falsified"}}, source)

    def test_reference_and_negative_results(self):
        text = summary("executable (exists-trace): verified (4 steps)", "authentication (all-traces): falsified - found trace (9 steps)")
        passed, actual, errors = proofctl.assess(text, 0, {"executable": "verified", "authentication": "falsified"})
        self.assertTrue(passed, errors)
        self.assertEqual(actual["authentication"], "falsified")

    def test_process_success_is_not_a_proof(self):
        self.assertFalse(proofctl.assess("", 0, {"authentication": "verified"})[0])

    def test_incomplete_analysis_fails(self):
        text = summary("authentication (all-traces): analysis incomplete (1 steps)")
        self.assertFalse(proofctl.assess(text, 0, {"authentication": "verified"})[0])

    def test_missing_and_extra_lemmas_fail(self):
        text = summary("extra (all-traces): verified (1 steps)")
        self.assertFalse(proofctl.assess(text, 0, {"authentication": "verified"})[0])

    def test_duplicate_summary_fails(self):
        text = summary("authentication (all-traces): verified (1 steps)", "authentication (all-traces): falsified (1 steps)")
        self.assertFalse(proofctl.assess(text, 0, {"authentication": "verified"})[0])

    def test_only_last_summary_counts(self):
        text = summary("authentication (all-traces): verified (1 steps)") + "\n" + summary("authentication (all-traces): falsified (1 steps)")
        self.assertEqual(proofctl.parse_summary(text), {"authentication": "falsified"})

    def test_trace_lemma_matching_handles_induction_without_prefix_collisions(self):
        self.assertTrue(proofctl.graph_matches_lemma("trace_Model_NB_authnon_empty_trace--Receive", "auth"))
        self.assertTrue(proofctl.graph_matches_lemma("trace_Model_NB_auth-Receive", "auth"))
        self.assertFalse(proofctl.graph_matches_lemma("trace_Model_NB_auth_injective-Receive", "auth"))
        self.assertFalse(proofctl.graph_matches_lemma("trace_Model_NB_other-Receive", "auth"))

    def test_failed_process_warning_and_timeout_fail(self):
        text = summary("authentication (all-traces): verified (1 steps)")
        expected = {"authentication": "verified"}
        self.assertFalse(proofctl.assess(text, 1, expected)[0])
        self.assertFalse(proofctl.assess("WARNING: unsound assumptions\n" + text, 0, expected)[0])
        self.assertFalse(proofctl.assess(text, 0, expected, timed_out=True)[0])

    def test_report_escapes_untrusted_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            record = {"model": "<script>", "variant": "reference", "passed": False, "actual": {},
                      "expected": {}, "errors": ["<img onerror='alert(1)'>"], "seconds": 1,
                      "artifacts": "<artifact>"}
            proofctl.write_report(output, [record], {})
            rendered = (output / "index.html").read_text()
            self.assertNotIn("<script>", rendered)
            self.assertNotIn("<img ", rendered)
            self.assertIn("&lt;script&gt;", rendered)

    def test_partial_report_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            proofctl.write_report(output, [], {}, expected_count=2)
            record = json.loads((output / "report.json").read_text())
            self.assertFalse(record["complete"])
            self.assertFalse(record["passed"])

    def test_trace_viewer_escapes_actions_and_keeps_causal_order_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            graph = {"jgLabel": "<script>", "jgNodes": [{"jgnId": "#a", "jgnType": "isProtocolRule",
                     "jgnLabel": "<rule>", "jgnMetadata": {"jgnActs": [{"jgnFactShow": "<img onerror=bad>"}]}}]}
            (output / "traces.json").write_text(json.dumps({"graphs": [graph]}))
            count, _ = proofctl.trace_viewer(output, render_svg=False)
            self.assertEqual(count, 1)
            rendered = (output / "traces.html").read_text()
            self.assertNotIn("<script>", rendered)
            self.assertNotIn("<img ", rendered)
            self.assertIn("not by row position", rendered)

    def test_run_case_enforces_timeout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fakebin = root / "bin"
            fakebin.mkdir()
            fake = fakebin / "tamarin-prover"
            fake.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(30)\n")
            fake.chmod(0o755)
            env = dict(os.environ)
            env["PATH"] = str(fakebin) + os.pathsep + env.get("PATH", "")
            model = proofctl.load_manifest()[0]
            result = proofctl.run_case(model, model["cases"][0], root / "out", 1, env)
            self.assertFalse(result["passed"])
            self.assertIn("proof timed out", result["errors"])
            self.assertLess(result["seconds"], 5)

    def test_success_summary_without_a_proof_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            fake = root / "tamarin-prover"
            model = proofctl.load_manifest()[0]
            case = model["cases"][0]
            output = summary(*(f"{name} ({'exists-trace' if name == 'executable' else 'all-traces'}): verified (1 steps)"
                               for name in case["expect"]))
            fake.write_text(f"#!{sys.executable}\nprint({output!r})\n")
            fake.chmod(0o755)
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ.get("PATH", ""))
            result = proofctl.run_case(model, case, root / "out", 5, env)
            self.assertFalse(result["passed"])
            self.assertIn("trace export failed: missing completed proof artifact", result["errors"])

    def test_manifest_covers_every_source_lemma(self):
        self.assertGreaterEqual(len(proofctl.load_manifest()), 1)

    def test_snapshot_copies_nested_includes_and_ignores_commented_directives(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "parts").mkdir()
            (root / "main.spthy").write_text('/* #include "missing" */\n#include "parts/rules.spthy"\n')
            (root / "parts/rules.spthy").write_text('#include "more.spthy"\n')
            (root / "parts/more.spthy").write_text('rule Example: [] --> []\n')
            with patch.object(proofctl, "ROOT", root):
                source, hashes = proofctl.snapshot_sources(root / "main.spthy", root / "out")
            self.assertEqual(len(hashes), 3)
            self.assertEqual((source.parent / "parts/more.spthy").read_text(), 'rule Example: [] --> []\n')
            (root / "parts/more.spthy").write_text("changed")
            self.assertNotEqual((source.parent / "parts/more.spthy").read_text(), "changed")

    def test_snapshot_rejects_include_escape_and_unsupported_directive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "main.spthy"
            with patch.object(proofctl, "ROOT", root):
                for directive in ('#include "../outside.spthy"', '#include <unknown>'):
                    source.write_text(directive)
                    with self.assertRaises(ValueError):
                        proofctl.snapshot_sources(source, root / "out")


if __name__ == "__main__":
    unittest.main()
