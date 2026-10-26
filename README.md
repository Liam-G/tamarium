# Tamarium

Regression tests for Tamarin models: declare the outcomes you expect, check them
after every edit, and retain the proof and counterexample evidence.

Tamarium is for people who already write Tamarin theories and want repeatable
checks locally and in CI. It helps catch changed properties, accidentally weakened
claims, missing execution witnesses, and incomplete prover runs. You still need
to justify your model's assumptions and its relationship to the system you study.

## Try it

Requires Python 3.10 or later. The checksum-pinned bootstrap supports Linux
x86_64. Graphviz is optional for rendering causal graphs.

```sh
git clone https://github.com/Liam-G/tamarium.git
cd tamarium
python3 tools/bootstrap.py
python3 proofctl.py prove --output results/baseline
python3 proofctl.py audit
```

Open `results/baseline/index.html` for the proof report and causal trace links.
The three bundled teaching examples cover message authentication, nonce replay,
and encryption-key binding. Each has a passing reference and a deliberately
weakened variant with expected counterexamples. The audit independently removes
a check and requires designated properties to fail while execution stays possible.

## Use it with your own project

Create an editable starter outside the Tamarium checkout:

```sh
python3 proofctl.py init ../my-models --example replay
python3 proofctl.py prove --project ../my-models --output ../my-models/results/before
# Edit the theory in ../my-models/protocols/synthetic/.
python3 proofctl.py prove --project ../my-models --output ../my-models/results/after
python3 proofctl.py compare ../my-models/results/before/report.json ../my-models/results/after/report.json
```

`init` creates model/configuration files without overwriting an existing directory.
`--project` keeps your theories and results separate while using this runner and
its installed proof tools. The starter options are `message`, `replay`, and `secrecy`.
Replace the starter model and update `suite.json` as your project grows.

Comparison flags changed lemma formulas, outcomes, expected contracts, quantifiers, and
added/removed cases. Updating an expectation cannot conceal an outcome change.
Source/configuration hashes and tool changes are reported separately; timing
noise is ignored. A changed comparison exits nonzero for review, including when
you intentionally add coverage. Formula fingerprints are textual: editing
whitespace inside a formula also requests review.

## CI and retained evidence

```sh
python3 proofctl.py junit results/baseline/report.json --output results/junit.xml
python3 proofctl.py verify-evidence results/baseline/report.json
```

JUnit treats an expected counterexample as success. Failed contracts and
unfinished cases become failing tests. The command exits nonzero for a failed
or incomplete report, while still writing XML for your CI system.

`verify-evidence` checks stored source/configuration/artifact hashes, the saved
case declaration, prover-summary outcomes, and required execution/counterexample
graphs. It runs offline and does not require an installed prover. Hashes establish
consistency with the receipt; they do not authenticate its author or detect
someone deliberately rewriting both evidence and receipt.

The runner rejects warnings, timeouts, missing or unexpected lemmas, mismatched
outcomes, and missing proof/trace artifacts. Each run writes input snapshots,
hashes, logs, JSON/DOT traces and a local HTML report into a new directory.
Trace edges establish causal order; table row order does not.

| Result | Interpretation |
|---|---|
| Verified all-traces lemma | Property holds in the model |
| Falsified all-traces lemma | A counterexample exists in the model |
| Verified exists-trace lemma | Requested execution has a witness |
| Falsified exists-trace lemma | Requested execution is unreachable |
| Timeout or incomplete analysis | Inconclusive; contract fails |

These commands consume proof reports (`report.json`). Mutation audit receipts
use a separate format and currently have their own HTML/JSON reports.

See [the walkthrough and contract format](docs/workflow.md),
[example assumptions](docs/examples.md), and the executable
[GitHub Actions workflow](.github/workflows/proofs.yml).

## Development

```sh
python3 -m unittest discover -s tests -v
python3 proofctl.py validate
```

The hosted workflow runs unit tests, all six example contracts, all three
mutation experiments, evidence verification, JUnit export, a separate-project
run, and report comparison. It retains synthetic evidence as a CI artifact.

The bootstrap installs official Tamarin and Maude binaries under `.tools/` and
checks the SHA-256 values in `toolchain.json`. Their licenses and installation
instructions belong to their respective upstream projects; this Python
workbench uses the MIT license.

Results and tool caches are ignored by Git. Reports can include absolute paths,
command lines, model contents and trace values; review your own generated
evidence before sharing it. Execute theories and inputs you trust.
