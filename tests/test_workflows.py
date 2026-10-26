"""Regression consumers must preserve failed, missing, and changed obligations."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

import proofctl
from workflows import (compare_reports, contained, initialize, junit_xml,
                       read_report, verify_evidence)


def report_fixture():
    return {"schema": 1, "complete": True, "passed": True, "expected_cases": 1,
            "tools": {"tamarin": "1.12.0"}, "cases": [
                {"model": "example", "variant": "reference", "passed": True,
                 "expected": {"executable": "verified", "auth": "verified"},
                 "actual": {"executable": "verified", "auth": "verified"},
                 "quantifiers": {"executable": "exists-trace", "auth": "all-traces"},
                 "seconds": 1, "errors": [], "defines": []}]}


class ReportTests(unittest.TestCase):
    def load(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(data))
            return read_report(path)

    def test_reject_duplicate_cases_and_inconsistent_pass_flags(self):
        for mutation in ("duplicate", "pass", "complete", "outcomes", "count", "empty"):
            data = report_fixture()
            if mutation == "duplicate":
                data["cases"].append(deepcopy(data["cases"][0]))
                data["expected_cases"] = 2
            elif mutation == "pass":
                data["passed"] = False
            elif mutation == "complete":
                data["complete"] = False
            elif mutation == "outcomes":
                data["cases"][0]["actual"]["auth"] = "falsified"
            elif mutation == "count":
                data["expected_cases"] = True
            else:
                data["expected_cases"] = 0
                data["cases"] = []
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.load(data)

    def test_junit_expected_counterexample_is_success(self):
        data = report_fixture()
        data["cases"][0]["expected"]["auth"] = "falsified"
        data["cases"][0]["actual"]["auth"] = "falsified"
        root = ET.fromstring(junit_xml(self.load(data)))
        self.assertEqual(root.get("failures"), "0")
        self.assertEqual(len(root.findall("testcase")), 1)

    def test_junit_incomplete_report_includes_unexecuted_failures(self):
        data = report_fixture()
        data.update(expected_cases=3, complete=False, passed=False)
        root = ET.fromstring(junit_xml(self.load(data)))
        self.assertEqual(root.get("tests"), "3")
        self.assertEqual(root.get("failures"), "2")
        self.assertEqual(len(root.findall("testcase/failure")), 2)

    def test_junit_escapes_report_values(self):
        data = report_fixture()
        data["cases"][0].update(model='<project & "sample">', passed=False,
                                errors=["<failure>&detail"])
        data["passed"] = False
        root = ET.fromstring(junit_xml(self.load(data)))
        self.assertEqual(root.find("testcase").get("classname"), '<project & "sample">')
        self.assertIn("<failure>&detail", root.find("testcase/failure").text)

    def test_compare_does_not_hide_regression_when_expectations_change(self):
        before = report_fixture()
        after = deepcopy(before)
        after["cases"][0]["actual"]["auth"] = "falsified"
        after["cases"][0]["expected"]["auth"] = "falsified"
        result = compare_reports(self.load(before), self.load(after))
        self.assertFalse(result["passed"])
        self.assertEqual({item["change"] for item in result["changes"]}, {"actual", "expected"})

    def test_compare_detects_removed_case_and_added_case(self):
        before = report_fixture()
        after = deepcopy(before)
        after["cases"][0]["variant"] = "replacement"
        result = compare_reports(before, after)
        self.assertFalse(result["passed"])
        self.assertEqual({item["change"] for item in result["changes"]}, {"added", "removed"})

    def test_compare_timing_is_ignored_and_input_changes_are_informational(self):
        before = report_fixture()
        after = deepcopy(before)
        after["cases"][0].update(seconds=123, source_sha256="changed")
        result = compare_reports(before, after)
        self.assertTrue(result["passed"])
        self.assertEqual(result["changes"], [])
        self.assertEqual(len(result["input_changes"]), 1)

    def test_compare_requires_passing_baseline(self):
        before = report_fixture()
        before.update(complete=False, passed=False)
        with self.assertRaises(ValueError):
            compare_reports(before, report_fixture())

    def test_compare_detects_weakened_formula_even_if_outcome_stays_verified(self):
        before = report_fixture()
        after = deepcopy(before)
        before["cases"][0]["lemma_sha256"] = proofctl.lemma_fingerprints(
            'lemma auth: "All x #i. Accepted(x)@i ==> x = \'approved\'"')
        after["cases"][0]["lemma_sha256"] = proofctl.lemma_fingerprints(
            'lemma auth: "All x #i. Accepted(x)@i ==> x = x"')
        result = compare_reports(before, after)
        self.assertFalse(result["passed"])
        self.assertEqual(result["changes"][0]["change"], "lemma_sha256")

    def test_formula_fingerprints_ignore_external_comments_and_proof_scripts(self):
        source = 'lemma auth: "All x #i. Accepted(x)@i ==> x = x"'
        self.assertEqual(proofctl.lemma_fingerprints(source),
                         proofctl.lemma_fingerprints('// lemma fake: "F"\n' + source + '\nby sorry'))

    def test_compare_and_junit_exit_nonzero_for_failed_current_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = report_fixture()
            after = deepcopy(before)
            after["passed"] = False
            after["cases"][0].update(passed=False, errors=["proof timed out"], actual={})
            (root / "before.json").write_text(json.dumps(before))
            (root / "after.json").write_text(json.dumps(after))
            for args in (["compare", str(root / "before.json"), str(root / "after.json")],
                         ["junit", str(root / "after.json"), "--output", str(root / "junit.xml")]):
                result = subprocess.run([sys.executable, str(proofctl.CODE_ROOT / "proofctl.py"), *args],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr)
            self.assertEqual(ET.parse(root / "junit.xml").getroot().get("failures"), "1")


class ProjectTests(unittest.TestCase):
    def test_initialize_each_example_and_validate_external_project(self):
        with tempfile.TemporaryDirectory() as directory:
            for example in ("message", "replay", "secrecy"):
                project = initialize(Path(directory) / example, example)
                result = subprocess.run([sys.executable, str(proofctl.CODE_ROOT / "proofctl.py"),
                                         "validate", "--project", str(project)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"synthetic-{example}", result.stdout)
                self.assertFalse((project / "proofctl.py").exists())
                self.assertFalse((project / "results").exists())

    def test_initialize_preserves_existing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "existing"
            project.mkdir()
            (project / "keep.txt").write_text("keep")
            with self.assertRaises(ValueError):
                initialize(project)
            self.assertEqual(list(project.iterdir()), [project / "keep.txt"])
            self.assertEqual((project / "keep.txt").read_text(), "keep")

    def test_initialize_rejects_unknown_example_without_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "new"
            with self.assertRaises(ValueError):
                initialize(project, "unknown")
            self.assertFalse(project.exists())


class EvidenceTests(unittest.TestCase):
    def evidence(self, root):
        data = report_fixture()
        case = data["cases"][0]
        folder = root / "example/reference"
        (folder / "inputs/project/protocols").mkdir(parents=True)
        source = b"synthetic source"
        (folder / "source.spthy").write_bytes(source)
        (folder / "inputs/project/protocols/example.spthy").write_bytes(source)
        (folder / "inputs/suite.json").write_text("{}")
        (folder / "inputs/case.json").write_text(json.dumps({"model": {"id": "example"},
            "case": {"id": "reference", "expect": case["expected"], "defines": []}}))
        (folder / "proof.spthy").write_text("synthetic proof")
        (folder / "traces.dot").write_text("digraph {}")
        (folder / "traces.json").write_text(json.dumps({"graphs": [{"jgLabel": "trace_example_executable-Send"}]}))
        (folder / "run.log").write_text("summary of summaries:\n"
            "  executable (exists-trace): verified (1 steps)\n"
            "  auth (all-traces): verified (1 steps)\n")
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        case.update(artifacts="example/reference", returncode=0,
                    source_sha256=hashlib.sha256(source).hexdigest(),
                    source_inputs={"protocols/example.spthy": hashlib.sha256(source).hexdigest()},
                    metadata_inputs={"suite.json": digest(folder / "inputs/suite.json")},
                    artifact_sha256={name: digest(folder / name) for name in
                                     ("proof.spthy", "traces.dot", "traces.json", "run.log")})
        return data, folder

    def test_verify_evidence_catches_tampered_artifact_input_and_source_copy(self):
        for name in ("proof.spthy", "inputs/suite.json", "inputs/project/protocols/example.spthy", "source.spthy"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                data, folder = self.evidence(root)
                self.assertEqual(verify_evidence(root / "report.json", data), [])
                (folder / name).write_text("changed")
                self.assertTrue(verify_evidence(root / "report.json", data))

    def test_verify_evidence_catches_missing_exported_witness(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data, folder = self.evidence(root)
            (folder / "traces.json").write_text('{"graphs": []}')
            data["cases"][0]["artifact_sha256"]["traces.json"] = hashlib.sha256((folder / "traces.json").read_bytes()).hexdigest()
            self.assertIn("Missing execution/counterexample trace", verify_evidence(root / "report.json", data)[0])

    def test_evidence_path_rejects_absolute_parent_and_symlink_escape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "evidence"
            root.mkdir()
            (root / "escape").symlink_to(root.parent, target_is_directory=True)
            for path in ("../outside", "/outside", "escape/outside"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    contained(root, path)

    def test_verify_evidence_catches_passing_report_with_failed_process(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data, _ = self.evidence(root)
            data["cases"][0]["returncode"] = 1
            self.assertIn("contradicts saved process result", verify_evidence(root / "report.json", data)[0])


if __name__ == "__main__":
    unittest.main()
