"""Project onboarding and offline consumers of proof-contract reports."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET


COMMANDS = {"init", "compare", "junit", "verify-evidence"}


def initialize(destination: Path, example: str = "message") -> Path:
    """Create a project atomically, without overwriting an existing path."""
    import proofctl
    source = proofctl.CODE_ROOT
    suite = json.loads((source / "suite.json").read_text())
    model = next((item for item in suite["models"]
                  if item["id"] == f"synthetic-{example}"), None)
    if model is None:
        raise ValueError(f"Unknown example: {example}")
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError(f"Destination already exists: {destination}")
    policy = json.loads((source / "assurance.json").read_text())
    with tempfile.TemporaryDirectory(prefix="tamarium-init-", dir=destination.parent) as temporary:
        root = Path(temporary) / "project"
        root.mkdir()
        target = root / model["path"]
        target.parent.mkdir(parents=True)
        shutil.copyfile(source / model["path"], target)
        shutil.copyfile(source / "toolchain.json", root / "toolchain.json")
        (root / "suite.json").write_text(json.dumps({"schema": 1, "models": [model]}, indent=2) + "\n")
        (root / "assurance.json").write_text(json.dumps({"schema": 1, "models": {
            model["id"]: policy["models"][model["id"]]}}, indent=2) + "\n")
        (root / ".gitignore").write_text("results/\n.tools/\n__pycache__/\n*.pyc\n")
        root.rename(destination)
    return destination


def read_report(path: Path) -> dict:
    """Reject ambiguous and internally inconsistent reports before using them."""
    report = json.loads(path.read_text())
    if not isinstance(report, dict) or report.get("schema") != 1 or not isinstance(report.get("cases"), list):
        raise ValueError("Expected a schema-1 proof report with cases")
    count = report.get("expected_cases")
    if type(count) is not int or count < 1 or count < len(report["cases"]):
        raise ValueError("Invalid expected case count")
    seen = set()
    for case in report["cases"]:
        if not isinstance(case, dict):
            raise ValueError("Invalid case record")
        key = (case.get("model"), case.get("variant"))
        if any(not isinstance(item, str) or not item for item in key) or key in seen:
            raise ValueError("Invalid or duplicate case identity")
        seen.add(key)
        if type(case.get("passed")) is not bool:
            raise ValueError("Case passed must be boolean")
        for field in ("actual", "expected"):
            values = case.get(field)
            allowed = {"verified", "falsified", "analysis incomplete"} if field == "actual" else {"verified", "falsified"}
            if not isinstance(values, dict) or any(not isinstance(k, str) or v not in allowed for k, v in values.items()):
                raise ValueError(f"Invalid {field} lemma map")
        if not case["expected"]:
            raise ValueError("Case has no expected obligations")
        if case["passed"] and (case["actual"] != case["expected"] or case.get("errors")
                               or "analysis incomplete" in case["actual"].values()):
            raise ValueError("Passing case contradicts its outcomes")
    complete = len(report["cases"]) == count
    passed = complete and all(case["passed"] for case in report["cases"])
    if report.get("complete") is not complete or report.get("passed") is not passed:
        raise ValueError("Report completion/pass flags contradict case records")
    return report


def compare_reports(before: dict, after: dict) -> dict:
    """A changed contract cannot conceal a changed proof result."""
    if not before["complete"] or not before["passed"]:
        raise ValueError("Comparison baseline must be complete and passing")
    left = {(row["model"], row["variant"]): row for row in before["cases"]}
    right = {(row["model"], row["variant"]): row for row in after["cases"]}
    changes, inputs = [], []
    for key in sorted(left.keys() | right.keys()):
        old, new = left.get(key), right.get(key)
        if old is None or new is None:
            changes.append({"model": key[0], "variant": key[1], "change": "added" if old is None else "removed"})
            continue
        for field in ("actual", "expected", "quantifiers", "lemma_sha256", "passed"):
            if old.get(field) != new.get(field):
                changes.append({"model": key[0], "variant": key[1], "change": field,
                                "before": old.get(field), "after": new.get(field)})
        for field in ("source_sha256", "source_inputs", "metadata_inputs", "defines"):
            if old.get(field) != new.get(field):
                inputs.append({"model": key[0], "variant": key[1], "change": field})
    return {"schema": 1, "passed": not changes and after["complete"] and after["passed"],
            "changes": changes, "input_changes": inputs,
            "tools_changed": before.get("tools") != after.get("tools"),
            "current_complete": after["complete"], "current_passed": after["passed"]}


def junit_xml(report: dict) -> str:
    """Expected counterexamples pass; incomplete runs produce failing tests."""
    root = ET.Element("testsuite", name="Tamarium", tests=str(report["expected_cases"]))
    failures = 0
    for case in report["cases"]:
        test = ET.SubElement(root, "testcase", classname=case["model"], name=case["variant"])
        if not case["passed"]:
            failures += 1
            failure = ET.SubElement(test, "failure", message="Proof contract failed")
            failure.text = json.dumps({"expected": case["expected"], "actual": case["actual"],
                                       "errors": case.get("errors", [])}, indent=2)
        ET.SubElement(test, "system-out").text = json.dumps(case["actual"], sort_keys=True)
    for index in range(report["expected_cases"] - len(report["cases"])):
        failures += 1
        test = ET.SubElement(root, "testcase", classname="Tamarium", name=f"unexecuted-{index + 1}")
        ET.SubElement(test, "failure", message="Run incomplete: expected case did not finish")
    root.set("failures", str(failures))
    root.set("errors", "0")
    return ET.tostring(root, encoding="unicode", xml_declaration=True) + "\n"


def contained(root: Path, relative: str) -> Path:
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"Unsafe evidence path: {relative}")
    target = (root / path).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError(f"Evidence path escapes its root: {relative}")
    return target


def verify_evidence(report_path: Path, report: dict) -> list[str]:
    """Check retained bytes and replay the runner's result/trace validation.

    A checksum verifies consistency with this receipt, not authenticity: this
    function cannot detect someone deliberately rewriting both files and hashes.
    """
    import proofctl
    errors = []
    if not report["complete"]:
        errors.append("Run is incomplete")
    for case in report["cases"]:
        label = f"{case['model']}/{case['variant']}"
        try:
            folder = contained(report_path.resolve().parent, case["artifacts"])
            artifacts = case["artifact_sha256"]
            if not {"proof.spthy", "traces.json", "traces.dot", "run.log"} <= artifacts.keys():
                raise ValueError("Missing required proof artifact hashes")
            if not case["source_inputs"] or not case["metadata_inputs"]:
                raise ValueError("Missing input hashes")
            for prefix, hashes in (("", artifacts), ("inputs", case["metadata_inputs"]),
                                   ("inputs/project", case["source_inputs"])):
                for name, digest in hashes.items():
                    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                        raise ValueError(f"Invalid SHA-256 for {name}")
                    # Validate name itself as well: an absolute name would
                    # otherwise discard the prefix in Path's join operation.
                    contained(folder, name)
                    target = contained(folder, str(Path(prefix) / name))
                    if hashlib.sha256(target.read_bytes()).hexdigest() != digest:
                        raise ValueError(f"SHA-256 mismatch: {name}")
            if hashlib.sha256((folder / "source.spthy").read_bytes()).hexdigest() != case["source_sha256"]:
                raise ValueError("SHA-256 mismatch: source.spthy")
            if ("lemma_sha256" in case and proofctl.lemma_fingerprints((folder / "source.spthy").read_text())
                    != case["lemma_sha256"]):
                raise ValueError("Saved lemma formulas differ from report")
            declaration = json.loads((folder / "inputs/case.json").read_text())
            if (declaration["model"]["id"], declaration["case"]["id"], declaration["case"]["expect"],
                declaration["case"]["defines"]) != (case["model"], case["variant"], case["expected"], case["defines"]):
                raise ValueError("Saved case declaration differs from report")
            log = (folder / "run.log").read_text()
            log_passed, actual, log_errors = proofctl.assess(log, case["returncode"], case["expected"])
            if case["passed"] and not log_passed:
                raise ValueError(f"Passing report contradicts saved process result: {log_errors}")
            if actual != case["actual"] or proofctl.parse_quantifiers(log) != case["quantifiers"]:
                raise ValueError("Saved prover summary differs from report")
            graphs = json.loads((folder / "traces.json").read_text())["graphs"]
            if not isinstance(graphs, list):
                raise ValueError("Invalid trace graph collection")
            for lemma, status in actual.items():
                needs_trace = ((status == "verified" and case["quantifiers"][lemma] == "exists-trace") or
                               (status == "falsified" and case["quantifiers"][lemma] == "all-traces"))
                if needs_trace and not any(proofctl.graph_matches_lemma(graph["jgLabel"], lemma) for graph in graphs):
                    raise ValueError(f"Missing execution/counterexample trace: {lemma}")
        except (OSError, ValueError, KeyError, TypeError) as error:
            errors.append(f"{label}: {error}")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Create a standalone project from a synthetic example")
    init.add_argument("directory", type=Path)
    init.add_argument("--example", default="message", choices=("message", "replay", "secrecy"))
    compare = commands.add_parser("compare", help="Detect changed outcomes, contracts, or case coverage")
    compare.add_argument("baseline", type=Path)
    compare.add_argument("current", type=Path)
    compare.add_argument("--output", type=Path)
    junit = commands.add_parser("junit", help="Export proof contracts as CI test results")
    junit.add_argument("report", type=Path)
    junit.add_argument("--output", type=Path, required=True)
    verify = commands.add_parser("verify-evidence", help="Check retained evidence against its receipt")
    verify.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            target = initialize(args.directory, args.example)
            print(f"Created project: {target}\nRun: python3 proofctl.py prove --project '{target}'")
            return 0
        if args.command == "compare":
            result = compare_reports(read_report(args.baseline), read_report(args.current))
            rendered = json.dumps(result, indent=2) + "\n"
            if args.output:
                args.output.write_text(rendered)
            print(rendered, end="")
            return 0 if result["passed"] else 1
        report = read_report(args.report)
        if args.command == "junit":
            args.output.write_text(junit_xml(report))
            print(f"JUnit report: {args.output}")
            return 0 if report["passed"] else 1
        errors = verify_evidence(args.report, report)
        for error in errors:
            print(error, file=sys.stderr)
        print(f"{'PASS' if not errors else 'FAIL'} evidence integrity ({len(report['cases'])} cases)")
        return 1 if errors else 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print(f"tamarium: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
