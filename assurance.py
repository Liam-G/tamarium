"""Measure declared claim sensitivity to independent, recorded rule mutations.

This checks a model's selected claims, not implementation security or novelty.
Mutations normally operate on Tamarin's closed baseline output. A constrained
original-source mode preserves embedded-guard metadata: it permits only a unique
unconditional rule in a proof-free, include-free source.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import difflib
import hashlib
import html
import json
from pathlib import Path
import re

import proofctl
from tamarin_text import code_mask

ROOT = Path(__file__).resolve().parent
DECLARATION = re.compile(r"(?m)^(?:lemma|rule|restriction|axiom|macros|functions|equations|builtins|tactic|heuristic|end)\b")


def original_unconditional_source(source: str, rule: str) -> str:
    """Preserve embedded restrictions without selecting inactive source rules.

    Tamarin's closed printer desugars embedded guards, losing their state-analysis
    metadata. This narrow alternative keeps them, rejecting includes, proof
    scripts, unsupported directives, and rules inside conditional blocks.
    """
    mask = code_mask(source, strings=True)
    if re.search(r"(?m)^\s*(?:by|solve|simplify|induction|SOLVED|case|next|qed)\b", mask):
        raise ValueError("Original-source mutations require a proof-free input")
    matches = list(re.finditer(r"(?m)^rule\s+" + re.escape(rule) + r"\s*:", mask))
    if len(matches) != 1:
        raise ValueError("Original-source mutation requires a unique rule")
    depth = 0
    for directive in re.finditer(r"(?m)^\s*#(\w+)\b", mask):
        word = directive[1]
        if word not in {"ifdef", "ifndef", "else", "endif"}:
            raise ValueError(f"Unsupported directive in original-source mode: {word}")
        if directive.start() >= matches[0].start():
            continue
        if word in {"ifdef", "ifndef"}:
            depth += 1
        elif word == "endif":
            depth -= 1
        if depth < 0:
            raise ValueError("Unbalanced preprocessor directives")
    if depth:
        raise ValueError("Selected original-source rule is conditional")
    # An include anywhere can hide rules or alter relative resolution.
    if re.search(r"(?m)^\s*#include\b", mask):
        raise ValueError("Original-source mode does not support includes")
    return source



def reset_proofs(source: str) -> str:
    """Discard every baseline proof script before proving a mutated theory."""
    mask = code_mask(source)
    declarations = list(DECLARATION.finditer(code_mask(source, strings=True)))
    edits = []
    for index, declaration in enumerate(declarations):
        if declaration.group() != "lemma":
            continue
        finish = declarations[index + 1].start() if index + 1 < len(declarations) else len(source)
        opening = mask.find('"', declaration.end(), finish)
        if opening < 0:
            raise ValueError("Lemma has no quoted formula")
        closing = opening + 1
        while closing < finish:
            if mask[closing] == "\\":
                closing += 2
                continue
            if mask[closing] == '"':
                break
            closing += 1
        if closing >= finish:
            raise ValueError("Unterminated lemma formula")
        edits.append((closing + 1, finish, "\nby sorry\n\n"))
    if not edits:
        raise ValueError("No lemma declarations to reset")
    for start, finish, replacement in reversed(edits):
        source = source[:start] + replacement + source[finish:]
    return source


def remove_action(source: str, selector: dict) -> tuple[str, dict]:
    """Remove exactly one selected action from exactly one named rule.

    This is a narrow transformer for closed MSR rules, not a Tamarin parser.
    It rejects ambiguous selection and Tamarin reparses every generated theory.
    """
    mask = code_mask(source, strings=True)
    rule = re.compile(r"(?m)^rule\s+(?:\(modulo\s+\w+\)\s+)?" + re.escape(selector["rule"]) + r"\s*:")
    matches = list(rule.finditer(mask))
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one rule {selector['rule']}, got {len(matches)}")
    start = matches[0].end()
    next_declaration = DECLARATION.search(mask, start)
    finish = next_declaration.start() if next_declaration else len(source)
    arrow = re.search(r"--\s*\[", mask[start:finish])
    if arrow is None:
        raise ValueError("Selected rule has no action list")
    begin = start + arrow.end()
    depth = 0
    actions = []
    left = begin
    cursor = begin
    while cursor < finish:
        char = mask[cursor]
        if char == "]" and depth == 0:
            actions.append(source[left:cursor].strip())
            break
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
            if depth < 0:
                raise ValueError("Unbalanced rule action")
        elif char == "," and depth == 0:
            actions.append(source[left:cursor].strip())
            left = cursor + 1
        cursor += 1
    else:
        raise ValueError("Unterminated action list")
    selected = []
    for index, action in enumerate(actions):
        cleaned = code_mask(action)
        if not re.match(r"^\s*" + re.escape(selector["predicate"]) + r"\s*\(", cleaned):
            continue
        if "contains_function" in selector and not re.search(r"\b" + re.escape(selector["contains_function"]) + r"\s*\(", code_mask(action, strings=True)):
            continue
        if "exact" in selector and re.sub(r"\s+", "", cleaned) != re.sub(r"\s+", "", selector["exact"]):
            continue
        selected.append(index)
    if len(selected) != 1:
        raise ValueError(f"Expected exactly one matching action, got {len(selected)}")
    deleted = actions.pop(selected[0])
    replacement = "\n      " + ",\n      ".join(action for action in actions if action) + "\n  "
    mutated = source[:begin] + replacement + source[cursor:]
    if mutated == source:
        raise ValueError("Mutation did not change the theory")
    return mutated, {"operator": "remove_action", "rule": selector["rule"], "removed": deleted,
                     "before_sha256": hashlib.sha256(source.encode()).hexdigest(),
                     "after_sha256": hashlib.sha256(mutated.encode()).hexdigest()}


def classify(reference: dict, experiment: dict, targets: list[str], witnesses: list[str], auxiliary: list[str] = ()) -> str:
    if not targets or not witnesses:
        return "invalid-policy"
    if not reference["passed"] or not experiment["passed"]:
        return "inconclusive"
    before, after = reference["actual"], experiment["actual"]
    if any(after.get(name) != "verified" for name in auxiliary):
        return "invalid-auxiliary"
    if any(before.get(name) != "verified" for name in targets + witnesses):
        return "invalid-baseline"
    if any(after.get(name) != "verified" for name in witnesses):
        return "execution-blocked"
    broken = [name for name in targets if after.get(name) == "falsified"]
    if len(broken) == len(targets):
        return "detected"
    return "partially-detected" if broken else "survived"


def validate_policy(model: dict, policy: dict) -> None:
    reference = next(case for case in model["cases"] if case["id"] == "reference")
    if reference["defines"] or any(value != "verified" for value in reference["expect"].values()):
        raise ValueError("Assurance baseline must have no defines and all claims verified")
    witnesses = policy.get("witnesses")
    if not isinstance(witnesses, list) or not witnesses or not set(witnesses) <= set(reference["expect"]):
        raise ValueError("Assurance policy requires declared baseline witnesses")
    experiments = policy.get("experiments")
    if not isinstance(experiments, list) or not experiments:
        raise ValueError("Assurance policy has no experiments")
    ids = set()
    for specification in experiments:
        name = specification["id"]
        if name == "reference" or name in ids or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
            raise ValueError("Invalid or duplicate assurance experiment ID")
        ids.add(name)
        if specification.get("source_form", "closed") not in {"closed", "original-unconditional"}:
            raise ValueError("Unsupported mutation source form")
        targets = specification.get("must_break")
        if (not isinstance(targets, list) or not targets or not set(targets) <= set(reference["expect"])
                or set(targets) & set(witnesses)):
            raise ValueError("Experiment requires nonempty security claims disjoint from witnesses")


def audit_model(model: dict, policy: dict, directory: Path, timeout: int, env: dict[str, str]) -> dict:
    validate_policy(model, policy)
    reference = next(case for case in model["cases"] if case["id"] == "reference")
    baseline = proofctl.run_case(model, reference, directory, timeout, env)
    result = {"model": model["id"], "baseline": baseline, "experiments": [], "complete": False}
    if not baseline["passed"]:
        return result
    if any(baseline["quantifiers"].get(name) != "exists-trace" for name in policy["witnesses"]):
        raise ValueError("Execution witnesses must be exists-trace lemmas")
    targets = {name for experiment in policy["experiments"] for name in experiment["must_break"]}
    if any(baseline["quantifiers"].get(name) != "all-traces" for name in targets):
        raise ValueError("Security targets must be all-traces lemmas")
    canonical = reset_proofs((directory / model["id"] / "reference/proof.spthy").read_text())
    original = (directory / model["id"] / "reference/source.spthy").read_text()
    (directory / model["id"] / "baseline-reset.spthy").write_text(canonical)
    auxiliary = re.findall(r"(?m)^lemma\s+(\w+)\s*\[[^\]]*\b(?:reuse|sources)\b[^\]]*\]", code_mask(canonical))
    result["auxiliary_lemmas"] = auxiliary
    for specification in policy["experiments"]:
        folder = directory / model["id"] / specification["id"]
        folder.mkdir(parents=True, exist_ok=False)
        try:
            source_form = specification.get("source_form", "closed")
            mutation_input = (original_unconditional_source(original, specification["remove_action"]["rule"])
                              if source_form == "original-unconditional" else canonical)
            mutated, transformation = remove_action(mutation_input, specification["remove_action"])
            transformation["source_form"] = source_form
        except ValueError as exc:
            result["experiments"].append({"id": specification["id"], "outcome": "inconclusive",
                                          "targets": specification["must_break"], "error": str(exc)})
            continue
        source = folder / "input.spthy"
        source.write_text(mutated)
        (folder / "transformation.json").write_text(json.dumps(transformation, indent=2) + "\n")
        (folder / "mutation.diff").write_text("".join(difflib.unified_diff(mutation_input.splitlines(True), mutated.splitlines(True), fromfile=f"baseline-{source_form}.spthy", tofile="input.spthy")))
        case = {"id": specification["id"], "defines": [], "expect": reference["expect"]}
        observed = proofctl.run_case(model, case, directory, timeout, env,
                                     source_override=source, compare_expectations=False)
        outcome = classify(baseline, observed, specification["must_break"], policy["witnesses"], auxiliary)
        result["experiments"].append({"id": specification["id"], "outcome": outcome,
                                      "targets": specification["must_break"], "observed": observed,
                                      "transformation": transformation})
        print(f"{outcome.upper()} {model['id']}/{specification['id']}", flush=True)
    result["complete"] = (len(result["experiments"]) == len(policy["experiments"])
                          and all(row["outcome"] != "inconclusive" for row in result["experiments"]))
    return result


def audit_suite(models: list[dict], args, env: dict[str, str], versions: dict[str, str]) -> int:
    policy = json.loads(proofctl.RUNTIME_INPUTS["assurance.json"])
    if policy.get("schema") != 1:
        raise ValueError("Unsupported assurance policy")
    selected = [model for model in models if model["id"] in policy["models"]]
    if args.model and len(selected) != len(models):
        raise ValueError("Some selected models have no assurance policy yet")
    if not selected:
        raise ValueError("No models have assurance policies")
    directory = (args.output or proofctl.ROOT / "results" / ("audit-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ"))).resolve()
    directory.mkdir(parents=True, exist_ok=False)
    metadata = proofctl.snapshot_metadata(directory)
    results = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(audit_model, model, policy["models"][model["id"]], directory, args.timeout, env): model["id"] for model in selected}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as error:
                results.append({"model": futures[future], "complete": False, "experiments": [],
                                "baseline": {"passed": False, "errors": [str(error)]}})
    complete = len(results) == len(selected) and all(row["complete"] for row in results)
    passed = complete and all(row["baseline"]["passed"] and row["experiments"]
                              and all(test["outcome"] == "detected" for test in row["experiments"]) for row in results)
    unassessed = [model["id"] for model in models if model["id"] not in policy["models"]]
    record = {"schema": 1, "complete": complete, "passed": passed, "tools": versions,
              "scope": "selected policies only", "metadata_inputs": metadata,
              "policy": policy, "results": results,
              "unassessed_models": unassessed,
              "limitations": "Selected mechanism-removal sensitivity only; no claim of protocol fidelity, mutation completeness or implementation security."}
    (directory / "assurance.json").write_text(json.dumps(record, indent=2) + "\n")
    rows = []
    for model in results:
        baseline_errors = "; ".join(model["baseline"].get("errors", []))
        rows.append(f"<tr><td>{html.escape(model['model'])}</td><td>baseline</td>"
                    f"<td>{'PASS' if model['baseline']['passed'] else 'FAIL'}</td>"
                    f"<td>{html.escape(baseline_errors)}</td><td>"
                    f"<a href='{html.escape(model['model'])}/reference/run.log'>log</a></td></tr>")
        for experiment in model["experiments"]:
            cells = (" · ".join(f"{name}: {status}" for name, status in experiment["observed"]["actual"].items())
                     if "observed" in experiment else experiment["error"])
            link = f"{model['model']}/{experiment['id']}"
            rows.append(f"<tr><td>{html.escape(model['model'])}</td><td>{html.escape(experiment['id'])}</td>"
                        f"<td>{html.escape(experiment['outcome'])}</td><td>{html.escape(cells)}</td>"
                        f"<td><a href='{link}/mutation.diff'>mutation</a> · <a href='{link}/traces.html'>trace</a></td></tr>")
    (directory / "index.html").write_text("""<!doctype html><html lang="en"><meta charset="utf-8"><title>Tamarium claim sensitivity</title>
<style>body{font:16px system-ui;margin:2rem}td,th{padding:12px;border:1px solid #bbb;text-align:left}table{border-collapse:collapse}p{max-width:85ch}</style>
<h1>Claim-to-mechanism sensitivity</h1><p>Each experiment independently removes one selected rule action.
Detected means all designated claims become false while the declared execution witnesses remain reachable.
Surviving mutations, blocked executions, partial detection and inconclusive searches fail this gate.
This gate does not establish protocol fidelity or research novelty.</p>
<table><tr><th>Model</th><th>Mechanism removed</th><th>Outcome</th><th>Claims</th><th>Evidence</th></tr>"""
        + "\n".join(rows) + f"</table><p>Selected policy gate: {'PASS' if passed else 'FAIL'}. "
        + f"Assessed {len(selected)} of {len(models)} selected models.</p><p>Unassessed selected models: "
        + html.escape(", ".join(unassessed) or "none") + "</p></html>\n")
    print(f"Assurance report: {directory / 'index.html'}", flush=True)
    return 0 if passed else 1
