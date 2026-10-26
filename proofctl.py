#!/usr/bin/env python3
"""Run Tamarin proof contracts and retain reproducible proof/attack artifacts."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import html
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

from tamarin_text import code_mask

CODE_ROOT = Path(__file__).resolve().parent
ROOT = CODE_ROOT
INPUT_NAMES = ("suite.json", "assurance.json", "toolchain.json",
               "proofctl.py", "assurance.py", "tamarin_text.py", "workflows.py")
# Keep the runner and configuration bytes seen by this interpreter. Later edits
# must not be recorded as though they were the code that executed a proof.
RUNTIME_INPUTS = {name: (ROOT / name).read_bytes() for name in INPUT_NAMES if (ROOT / name).exists()}
RUNTIME_PATHS = {name: ROOT / name for name in RUNTIME_INPUTS}
SUMMARY = re.compile(r"^\s+([A-Za-z_][\w]*)(?:\s+\[.*?\])?\s+\((all-traces|exists-trace)\):\s+(verified|falsified|analysis incomplete)\b", re.MULTILINE)
LEMMA = re.compile(r"^lemma\s+([A-Za-z_]\w*)", re.MULTILINE)
LEMMA_DECLARATION = re.compile(r"^lemma\s+([A-Za-z_]\w*)(?:\s*\[[^\]]*\])?\s*:\s*(exists-trace)?", re.MULTILINE)
CASE_KINDS = {"reference": "Reference", "seeded-defect": "Seeded defect",
              "policy-profile": "Policy profile", "implementation-profile": "Implementation profile",
              "known-regression": "Known regression", "independent-mutation": "Independent mutation",
              "implementation-hypothesis": "Implementation hypothesis"}


def validate_reference(case: dict, source: str) -> None:
    """Reference safety must hold; explicit negative reachability controls may fail.

    A falsified exists-trace lemma proves a forbidden schedule unreachable. It
    must not be confused with a falsified all-traces security obligation.
    """
    declarations = dict(LEMMA_DECLARATION.findall(code_mask(source, strings=True)))
    if case["defines"] or any(status != "verified" and declarations.get(name) != "exists-trace"
                              for name, status in case["expect"].items()):
        raise ValueError("Reference cases require no defines and verified all-traces obligations")


def configure_project(project: Path) -> None:
    """Keep project configuration separate from the executing runner's bytes."""
    global ROOT, RUNTIME_INPUTS, RUNTIME_PATHS
    ROOT = project.resolve()
    RUNTIME_PATHS = {name: (ROOT if name.endswith(".json") else CODE_ROOT) / name
                     for name in INPUT_NAMES}
    # An assurance policy is optional for projects that only run contracts.
    RUNTIME_INPUTS = {name: path.read_bytes() for name, path in RUNTIME_PATHS.items()
                      if path.is_file()}
    for required in ("suite.json", "toolchain.json"):
        if required not in RUNTIME_INPUTS:
            raise ValueError(f"Project is missing {required}: {ROOT}")


def load_manifest(path: Path | None = None) -> list[dict]:
    path = path or ROOT / "suite.json"
    data = json.loads(RUNTIME_INPUTS["suite.json"] if path == ROOT / "suite.json" else path.read_bytes())
    if data.get("schema") != 1 or not isinstance(data.get("models"), list) or not data["models"]:
        raise ValueError("Unsupported suite manifest")
    ids: set[str] = set()
    for model in data["models"]:
        name = model["id"]
        if not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name) or name in ids:
            raise ValueError(f"Invalid or duplicate model ID: {name}")
        ids.add(name)
        source = (ROOT / model["path"]).resolve()
        if not source.is_relative_to(ROOT / "protocols") or not source.is_file():
            raise ValueError(f"Invalid model path: {model['path']}")
        declarations = LEMMA.findall(code_mask(source.read_text(), strings=True))
        lemmas = set(declarations)
        if len(declarations) != len(lemmas):
            raise ValueError(f"Duplicate lemma names: {name}")
        if not lemmas or "executable" not in lemmas or not model["cases"]:
            raise ValueError(f"Model requires claims, an executable witness and cases: {name}")
        variants: set[str] = set()
        for case in model["cases"]:
            if case.get("kind", "reference" if case["id"] == "reference" else "seeded-defect") not in CASE_KINDS:
                raise ValueError("Unsupported case kind")
            if case["id"] in variants or not re.fullmatch(r"[a-z0-9-]+", case["id"]):
                raise ValueError(f"Invalid or duplicate variant: {case['id']}")
            variants.add(case["id"])
            if set(case["expect"]) != lemmas:
                raise ValueError(f"Contract must cover every lemma: {name}/{case['id']}")
            if any(value not in ("verified", "falsified") for value in case["expect"].values()):
                raise ValueError("Expected statuses must be verified or falsified")
            if case["expect"]["executable"] != "verified":
                raise ValueError("Declared protocol variants must retain their executable witness")
            if case["id"] == "reference":
                validate_reference(case, source.read_text())
            if any(not re.fullmatch(r"[A-Z][A-Z0-9_]*", define) for define in case["defines"]):
                raise ValueError("Invalid preprocessor definition")
        if "reference" not in variants:
            raise ValueError(f"Missing reference case: {name}")
    return data["models"]


def parse_summary(output: str) -> dict[str, str]:
    # Only accept the final CLI summary; pretty-printed theories and partial
    # diagnostics must never be mistaken for completed verification.
    marker = "summary of summaries:"
    if marker not in output:
        return {}
    found: dict[str, str] = {}
    for match in SUMMARY.finditer(output.rsplit(marker, 1)[1]):
        name, _, status = match.groups()
        if name in found:
            raise ValueError(f"Duplicate lemma in Tamarin summary: {name}")
        found[name] = status
    return found


def parse_quantifiers(output: str) -> dict[str, str]:
    if "summary of summaries:" not in output:
        return {}
    return {name: quantifier for name, quantifier, _ in
            SUMMARY.findall(output.rsplit("summary of summaries:", 1)[1])}


def lemma_fingerprints(source: str) -> dict[str, str]:
    """Retain formula bytes so unchanged names/statuses cannot hide edits."""
    comments_masked = code_mask(source)
    result = {}
    declarations = list(LEMMA_DECLARATION.finditer(code_mask(source, strings=True)))
    for index, declaration in enumerate(declarations):
        finish = declarations[index + 1].start() if index + 1 < len(declarations) else len(source)
        # The declaration regex's trailing whitespace can span a masked formula.
        # Start after the header colon rather than after that whitespace.
        start = comments_masked.index(":", declaration.start(), declaration.end()) + 1
        formula = re.search(r'"(?:\\.|[^"\\])*"', comments_masked[start:finish], re.DOTALL)
        if formula is None:
            raise ValueError(f"Missing formula: {declaration[1]}")
        result[declaration[1]] = hashlib.sha256(formula.group().encode()).hexdigest()
    return result


def graph_matches_lemma(label: str, lemma: str) -> bool:
    # Induction exports append the proof-case name directly to the lemma name.
    # Exact boundaries avoid confusing, e.g., auth and auth_injective.
    return re.search(r"(?:^|_)" + re.escape(lemma)
                     + r"(?=-|(?:non_empty_trace|empty_trace)(?:-|$)|$)", label) is not None


def assess(output: str, returncode: int, expected: dict[str, str], timed_out: bool = False) -> tuple[bool, dict[str, str], list[str]]:
    errors = []
    if timed_out:
        errors.append("proof timed out")
    if returncode != 0:
        errors.append(f"Tamarin exited with {returncode}")
    if re.search(r"\bWARNING\b|wellformedness checks failed", output):
        errors.append("Tamarin reported a warning")
    try:
        actual = parse_summary(output)
    except ValueError as exc:
        actual = {}
        errors.append(str(exc))
    if set(actual) != set(expected):
        errors.append(f"lemma set mismatch: missing={sorted(set(expected)-set(actual))}, unexpected={sorted(set(actual)-set(expected))}")
    for name, status in actual.items():
        if status == "analysis incomplete":
            errors.append(f"{name}: proof search is incomplete")
        if name in expected and status != expected[name]:
            errors.append(f"{name}: expected {expected[name]}, got {status}")
    return not errors, actual, errors


def tool_env() -> dict[str, str]:
    env = dict(os.environ)
    locations = list(dict.fromkeys([ROOT, CODE_ROOT]))
    env["PATH"] = os.pathsep.join([str(base / folder) for base in locations
                                     for folder in (".tools/bin", ".tools/maude")]
                                    + [env.get("PATH", "")])
    binary = shutil.which("maude", path=env["PATH"])
    if binary and (Path(binary).resolve().parent / "prelude.maude").is_file():
        env["MAUDE_LIB"] = str(Path(binary).resolve().parent)
    return env


def tool_versions(env: dict[str, str]) -> dict[str, str]:
    pins = json.loads(RUNTIME_INPUTS["toolchain.json"])
    versions = {}
    for name, executable in (("tamarin", "tamarin-prover"), ("maude", "maude")):
        binary = shutil.which(executable, path=env["PATH"])
        if not binary:
            raise ValueError("Missing proof tools. Run: python3 tools/bootstrap.py")
        version = subprocess.run([executable, "--version"], env=env, capture_output=True, text=True, timeout=15)
        output = version.stdout + version.stderr
        if version.returncode != 0 or not re.search(r"(?<![\d.])" + re.escape(pins[name]["version"]) + r"(?![\d.])", output):
            raise ValueError(f"Expected {executable} {pins[name]['version']}: {output[:300]}")
        versions[name] = pins[name]["version"]
        versions[f"{name}_binary_sha256"] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
    return versions


def trace_viewer(folder: Path, render_svg: bool = True) -> tuple[int, list[str]]:
    """Render Tamarin's graph data without interpreting nodes as a total order."""
    data = json.loads((folder / "traces.json").read_text())
    graphs = data["graphs"]
    if not isinstance(graphs, list):
        raise ValueError("Invalid trace graph collection")
    labels = [str(graph["jgLabel"]) for graph in graphs]
    if render_svg and shutil.which("dot") and (folder / "traces.dot").is_file():
        rendered = subprocess.run(["dot", "-Tsvg", "-O", "traces.dot"], cwd=folder, capture_output=True, text=True, timeout=30)
        if rendered.returncode:
            (folder / "render.log").write_text(rendered.stdout + rendered.stderr)
    panels = []
    for index, graph in enumerate(graphs):
        rows = []
        for node in graph.get("jgNodes", []):
            if node.get("jgnType") != "isProtocolRule":
                continue
            actions = "\n".join(str(act.get("jgnFactShow", "")) for act in node.get("jgnMetadata", {}).get("jgnActs", []))
            rows.append(f"<tr><td>{html.escape(str(node.get('jgnId', '')))}</td>"
                        f"<td>{html.escape(str(node.get('jgnLabel', '')))}</td><td><pre>{html.escape(actions)}</pre></td></tr>")
        svg = "traces.dot.svg" if index == 0 else f"traces.dot.{index + 1}.svg"
        picture = f"<a href='{svg}'>Open causal graph (SVG)</a>" if (folder / svg).is_file() else ""
        panels.append(f"<details><summary>{html.escape(labels[index])}</summary>{picture}"
                      "<table><thead><tr><th>Node</th><th>Rule</th><th>Events</th></tr></thead><tbody>"
                      + "\n".join(rows) + "</tbody></table></details>")
    (folder / "traces.html").write_text("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Tamarium traces</title>
<style>body{font:16px system-ui;margin:2rem;background:#10151c;color:#e4edf5}a{color:#8cd4ff}
details{margin:1rem 0;padding:1rem;border:1px solid #456}summary{cursor:pointer;overflow-wrap:anywhere}
td,th{padding:10px;text-align:left;vertical-align:top;border-bottom:1px solid #345}pre{white-space:pre-wrap}</style>
<h1>Execution and attack traces</h1><p>Graphs include executability witnesses and security counterexamples.
Compare each graph's lemma name with report.json. Rows list graph nodes; causal order is defined by the
edges in the SVG, DOT and JSON graphs, not by row position.</p>""" + "\n".join(panels) + "</html>\n")
    return len(graphs), labels


def snapshot_sources(source: Path, folder: Path) -> tuple[Path, dict[str, str]]:
    """Copy a complete relative include tree, preserving Tamarin's resolution."""
    inputs = folder / "inputs" / "project"
    source = source.resolve()
    base = ROOT if source.is_relative_to(ROOT) else source.parent
    hashes: dict[str, str] = {}
    def copy(path: Path) -> Path:
        path = path.resolve()
        if not path.is_relative_to(base):
            raise ValueError(f"Source/include escapes its snapshot root: {path}")
        relative = path.relative_to(base)
        identifier = str(relative) if base == ROOT else str(path)
        target = inputs / relative
        if identifier in hashes:
            return target
        data = path.read_bytes()
        hashes[identifier] = hashlib.sha256(data).hexdigest()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        mask = code_mask(data.decode())
        for directive in re.finditer(r'(?m)^\s*#include\b[^\n]*', mask):
            match = re.fullmatch(r'\s*#include\s+"([^"\n]+)"\s*', directive.group())
            if match is None:
                raise ValueError("Unsupported include directive; refusing an incomplete snapshot")
            copy(path.parent / match[1])
        return target
    return copy(source), hashes


def snapshot_metadata(folder: Path) -> dict[str, str]:
    hashes = {}
    for name, data in RUNTIME_INPUTS.items():
        destination = folder / "inputs" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    return hashes


def run_case(model: dict, case: dict, directory: Path, timeout: int, env: dict[str, str],
             *, source_override: Path | None = None, compare_expectations: bool = True) -> dict:
    folder = directory / model["id"] / case["id"]
    folder.mkdir(parents=True, exist_ok=True)
    source_path = source_override or ROOT / model["path"]
    input_path, source_hashes = snapshot_sources(source_path, folder)
    source_bytes = input_path.read_bytes()
    (folder / "source.spthy").write_bytes(source_bytes)
    metadata_hashes = snapshot_metadata(folder)
    (folder / "inputs" / "case.json").write_text(json.dumps({"model": model, "case": case}, indent=2) + "\n")
    command = ["tamarin-prover", str(input_path), "--prove", "--quit-on-warning", "--derivcheck-timeout=20",
               f"--output={folder / 'proof.spthy'}", f"--output-json={folder / 'traces.json'}",
               f"--output-dot={folder / 'traces.dot'}"]
    command.extend(f"-D={define}" for define in case["defines"])
    command += ["+RTS", "-N1", "-RTS"]
    started = time.monotonic()
    timed_out = False
    # Kill the whole process group on timeout, including Maude children.
    with (folder / "run.log").open("w") as log:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                returncode = process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                returncode = process.wait()
    output = (folder / "run.log").read_text(errors="replace")
    try:
        observed = parse_summary(output)
    except ValueError:
        observed = {}  # assess() records malformed summaries as failures.
    expected = case["expect"] if compare_expectations else {
        name: observed.get(name, "verified") for name in case["expect"]}
    passed, actual, errors = assess(output, returncode, expected, timed_out)
    quantifiers = parse_quantifiers(output)
    for relative, digest in source_hashes.items():
        original = ROOT / relative
        if not original.exists() or hashlib.sha256(original.read_bytes()).hexdigest() != digest:
            errors.append(f"model source changed while the proof was running: {relative}")
    for name, digest in metadata_hashes.items():
        path = RUNTIME_PATHS[name]
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            errors.append(f"runner/configuration changed during this invocation: {name}")
    trace_count = 0
    artifact_hashes = {}
    if not timed_out and returncode == 0:
        try:
            proof = folder / "proof.spthy"
            if not proof.is_file() or not proof.stat().st_size:
                raise ValueError("missing completed proof artifact")
            trace_count, labels = trace_viewer(folder)
            for lemma, status in actual.items():
                if (status == "falsified" and quantifiers.get(lemma) == "all-traces"
                        and not any(graph_matches_lemma(label, lemma) for label in labels)):
                    errors.append(f"missing exported counterexample for {lemma}")
                if (status == "verified" and quantifiers.get(lemma) == "exists-trace"
                        and not any(graph_matches_lemma(label, lemma) for label in labels)):
                    errors.append(f"missing exported execution witness for {lemma}")
            for name in ("proof.spthy", "traces.json", "traces.dot", "run.log"):
                path = folder / name
                if not path.is_file():
                    raise ValueError(f"missing artifact: {name}")
                artifact_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            errors.append(f"trace export failed: {exc}")
    passed = passed and not errors
    return {"model": model["id"], "variant": case["id"], "passed": passed,
            "kind": (case.get("kind", "reference" if case["id"] == "reference" else "seeded-defect")
                     if compare_expectations else "independent-mutation"),
            "seconds": round(time.monotonic() - started, 2), "returncode": returncode,
            "expected": case["expect"] if compare_expectations else None,
            "comparison": "contract" if compare_expectations else "observation",
            "actual": actual, "quantifiers": quantifiers, "errors": errors,
            "source_sha256": hashlib.sha256(source_bytes).hexdigest(), "trace_count": trace_count,
            "lemma_sha256": lemma_fingerprints(source_bytes.decode()),
            "source_inputs": source_hashes, "metadata_inputs": metadata_hashes,
            "artifact_sha256": artifact_hashes,
            "defines": case["defines"], "command": command,
            "artifacts": str(folder.relative_to(directory))}


def write_report(directory: Path, results: list[dict], versions: dict[str, str], expected_count: int | None = None) -> None:
    total = len(results) if expected_count is None else expected_count
    complete = len(results) == total
    record = {"schema": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
              "tools": versions, "complete": complete, "expected_cases": total,
              "passed": complete and all(row["passed"] for row in results), "cases": results,
              "metadata_inputs": sorted({(name, digest) for row in results
                                         for name, digest in row.get("metadata_inputs", {}).items()})}
    (directory / "report.json").write_text(json.dumps(record, indent=2) + "\n")
    rows = []
    for row in results:
        actual = "; ".join(f"{name}: {status}" for name, status in row["actual"].items())
        errors = "; ".join(row["errors"])
        detail = "; ".join(part for part in (actual, errors) if part)
        status = "PASS" if row["passed"] else "FAIL"
        folder = html.escape(row["artifacts"], quote=True)
        kind = CASE_KINDS.get(row.get("kind"), "")
        variant = row["variant"] + (f" · {kind}" if kind else "")
        rows.append(f"<tr><td>{html.escape(row['model'])}</td><td>{html.escape(variant)}</td>"
                    f"<td class='{status.lower()}'>{status}</td><td>{html.escape(detail)}</td>"
                    f"<td>{row['seconds']:.2f}s</td><td><a href='{folder}/run.log'>log</a> · "
                    f"<a href='{folder}/proof.spthy'>proof</a> · <a href='{folder}/traces.html'>trace viewer</a></td></tr>")
    (directory / "index.html").write_text("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Tamarium proof report</title>
<style>body{font:16px system-ui;max-width:1400px;margin:3rem auto;padding:0 1rem;background:#10151c;color:#e4edf5}
a{color:#8cd4ff}table{border-collapse:collapse;width:100%}td,th{padding:12px;border-bottom:1px solid #334;text-align:left}
.pass{color:#80e0a0}.fail{color:#ff9696}p{max-width:80ch;line-height:1.6}td:nth-child(4){font-family:monospace;font-size:13px}</style>
<h1>Tamarium proof contracts</h1><p>PASS means every lemma matches its declared expectation.
Cases include optional policies, implementation profiles, known regressions and deliberately seeded defects.
A falsified exists-trace lemma means that requested execution is unreachable; this is not an attack.
These are symbolic model results. Timeouts, missing lemmas and warnings fail the run.</p>
<table><thead><tr><th>Model</th><th>Variant</th><th>Contract</th><th>Tamarin results</th><th>Time</th><th>Artifacts</th></tr></thead>
<tbody>""" + "\n".join(rows) + f"</tbody></table><p>{len(results)}/{total} cases completed.</p></html>\n")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"init", "compare", "junit", "verify-evidence"}:
        from workflows import main as workflow_main
        return workflow_main(argv)
    parser = argparse.ArgumentParser(description=__doc__, epilog=(
        "Project/report commands: init DIRECTORY [--example message|replay|secrecy], "
        "compare BASELINE CURRENT, junit REPORT --output FILE, verify-evidence REPORT. "
        "Run each command with --help for details."))
    parser.add_argument("command", choices=("list", "validate", "doctor", "prove", "audit"))
    parser.add_argument("--model", action="append", default=[], help="Repeat to select models; default all")
    parser.add_argument("--variant", choices=("all", "reference", "negative"), default="all",
                        help="negative selects every non-reference case, including policy profiles")
    parser.add_argument("--timeout", type=int, default=90, help="Seconds per theory variant")
    parser.add_argument("--jobs", type=int, default=2)
    parser.add_argument("--output", type=Path, help="New output directory (never reuse one)")
    parser.add_argument("--project", type=Path, default=CODE_ROOT, help="Project containing suite.json and protocols/")
    args = parser.parse_args(argv)
    try:
        configure_project(args.project)
        if args.timeout <= 0 or args.jobs <= 0:
            raise ValueError("timeout and jobs must be positive")
        models = load_manifest()
        unknown = set(args.model) - {m["id"] for m in models}
        if unknown:
            raise ValueError(f"Unknown models: {sorted(unknown)}")
        models = [m for m in models if not args.model or m["id"] in args.model]
        if args.command in ("list", "validate"):
            for model in models:
                print(f"{model['id']:20} {model['path']} ({len(model['cases'])} variants)")
            print(f"Validated {len(models)} model contracts")
            return 0
        env = tool_env()
        versions = tool_versions(env)
        if args.command == "doctor":
            print(json.dumps(versions, indent=2))
            return 0
        if args.command == "audit":
            if "assurance.json" not in RUNTIME_INPUTS:
                raise ValueError("Project has no assurance.json mutation policy")
            from assurance import audit_suite
            return audit_suite(models, args, env, versions)
        directory = (args.output or ROOT / "results" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")).resolve()
        directory.mkdir(parents=True, exist_ok=False)
        work = [(model, case) for model in models for case in model["cases"]
                if args.variant == "all" or (case["id"] == "reference") == (args.variant == "reference")]
        if not work:
            raise ValueError("No cases selected")
        (directory / "suite.json").write_bytes(RUNTIME_INPUTS["suite.json"])
        (directory / "toolchain.json").write_bytes(RUNTIME_INPUTS["toolchain.json"])
        results = []
        write_report(directory, [], versions, len(work))
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futures = [pool.submit(run_case, model, case, directory, args.timeout, env) for model, case in work]
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                print(f"{'PASS' if result['passed'] else 'FAIL'} {result['model']}/{result['variant']} ({result['seconds']}s)", flush=True)
                for error in result["errors"]:
                    print(f"  {error}", flush=True)
                write_report(directory, sorted(results, key=lambda row: (row["model"], row["variant"])), versions, len(work))
        print(f"Report: {directory / 'index.html'}")
        return 0 if all(row["passed"] for row in results) else 1
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, json.JSONDecodeError) as exc:
        print(f"proofctl: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.modules["proofctl"] = sys.modules[__name__]
    raise SystemExit(main())
