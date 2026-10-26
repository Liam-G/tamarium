# A repeatable model review workflow

Use Tamarium when a Tamarin theory is already useful and you want to notice
changes to its behavior. Prover installation is required for `prove` and `audit`;
initialization, manifest validation, report comparison, JUnit export, and evidence
verification do not invoke the prover.

## Start with a contract

`python3 proofctl.py init ../my-models --example message` creates a small project.
Run commands from the Tamarium checkout with `--project ../my-models`.
Installed tools are searched first in the selected project, then in the runner's
checkout, then on `PATH`. Versions must match the project's `toolchain.json`.

Edit the model and describe every expected lemma in `suite.json`:

```json
{
  "schema": 1,
  "models": [{
    "id": "synthetic-message",
    "path": "protocols/synthetic/message.spthy",
    "cases": [
      {"id": "reference", "defines": [], "expect": {
        "executable": "verified", "message_authentication": "verified"
      }},
      {"id": "omit-check", "defines": ["OMIT_CHECK"], "expect": {
        "executable": "verified", "message_authentication": "falsified"
      }}
    ]
  }]
}
```

Paths must resolve inside `protocols/`. IDs are lowercase words separated by
hyphens; preprocessor definitions are uppercase identifiers. Every model needs
a `reference` case and an `executable` witness expected to verify in every case.
Reference cases use no definitions and require verified safety properties.
Explicitly unreachable exists-trace controls may be expected to falsify.

All lemmas declared directly in a theory must appear in every case's expectation
map. Keep includes for supporting rules/functions; the manifest reader currently
does not discover lemma declarations in included files. The evidence snapshot
retains transitive relative includes and rejects paths outside the project.

Validate before invoking Tamarin:

```sh
python3 proofctl.py validate --project ../my-models
python3 proofctl.py prove --project ../my-models --jobs 2 --timeout 60 --output ../my-models/results/before
```

Each selected case has its own timeout, including derivation checks and artifact
export. A timeout terminates the prover process group. A partially completed run
has `complete: false` and fails. Output directories must be new.

## Review changes

After editing, run into `results/after`, then compare the two `report.json` files.
The baseline must be complete and passing. Exit zero means case coverage,
expected results, actual results, lemma formula fingerprints and recorded quantifiers are unchanged, and the
current report passes. Added/removed cases and any of those changes exit one.
Invalid reports or an unusable baseline exit two.

```sh
python3 proofctl.py compare ../my-models/results/before/report.json ../my-models/results/after/report.json --output comparison.json
```

The JSON comparison also lists input changes and a tool-change indicator.
These are informational: source edits that preserve outcomes do not fail this
comparison. Formula fingerprints flag changed claim text even if its name and
verified status stay the same. They are textual checks, so whitespace edits
inside a formula also request review. Older reports without fingerprints remain
readable; comparing them to new reports flags the missing fingerprint field.
The command does not check semantic equivalence of theories, proof scripts or
graph structure; review model diffs as well.

## Check claim sensitivity

An assurance policy names the execution witnesses to preserve and the properties
that must fail when a selected action is removed:

```json
{
  "schema": 1,
  "models": {"synthetic-message": {
    "witnesses": ["executable"],
    "experiments": [{
      "id": "remove-signature-check",
      "remove_action": {"rule": "Receive", "predicate": "Eq", "contains_function": "verify"},
      "must_break": ["message_authentication"]
    }]
  }}
}
```

`python3 proofctl.py audit --project ../my-models` first proves the reference,
removes exactly one selected action from its closed theory, discards existing
proof scripts, and reruns the obligations. Ambiguous selections fail. Surviving
mutations, blocked executions, partially detected targets and inconclusive
searches all fail the selected policy gate. The receipt retains the exact diff.
This tests selected claims' sensitivity; it cannot establish model fidelity or
exhaustive mutation coverage. An `assurance.json` policy is optional for projects
that run only proof contracts.

## Export and check evidence

`junit REPORT --output FILE` exports one test per case and failing placeholders
for expected cases that did not finish. An expected falsified security property
in a deliberately weakened case passes when the contract matches and the
required counterexample was exported. JUnit export exits one for failed or
incomplete reports and two for malformed reports.

`verify-evidence REPORT` checks retained evidence without running a prover.
It exits zero for consistent evidence, one for missing/altered/incomplete
evidence, and two for a malformed report. A complete report can describe a
failed contract and still have consistent evidence: integrity and property
success are separate checks. A timed-out case normally lacks completed proof
artifacts and therefore fails evidence verification.

Receipts are unsigned. Keep an independently trusted copy or hash if you need
to detect deliberate rewriting of both artifacts and receipts. Paths in evidence
must stay within their case directory; source snapshots use relative project
paths. HTML views are generated conveniences rather than hashed proof artifacts.
