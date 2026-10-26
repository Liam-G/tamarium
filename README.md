# Tamarium

A small workbench for reproducible Tamarin proof contracts and mutation checks.
Requires Python 3.10 or later. The bundled bootstrap supports Linux x86_64.
Graphviz is optional for rendering causal graphs.

```sh
python3 tools/bootstrap.py
python3 -m unittest discover -s tests -v
python3 proofctl.py validate
python3 proofctl.py prove --jobs 1 --timeout 60
python3 proofctl.py audit --jobs 1 --timeout 60
```

The bootstrap downloads checksum-pinned Tamarin and Maude binaries into
`.tools/`. Their licenses and installation details are available from their
respective upstream projects. These binaries are installed separately from
this MIT-licensed Python workbench.

The included synthetic example verifies signed-message authentication. A
deliberately weakened variant omits signature validation and must falsify that
property while retaining its execution witness. The independent audit removes
the validation action from the completed reference theory and checks whether
the property detects the change.

`suite.json` declares every model, variant, flag and expected lemma result.
`assurance.json` declares mutation experiments and the claims they must break.
Use the synthetic example as a template for your own models under `protocols/`.

The runner rejects warnings, timeouts, missing or unexpected lemmas, mismatched
outcomes, and missing proof/trace artifacts. Each run writes input snapshots,
hashes, logs, JSON/DOT traces and a local HTML report into a new `results/`
directory. Trace edges establish causal order; table row order does not.

A verified all-traces lemma is a model property. A falsified all-traces lemma
has a counterexample. A verified exists-trace lemma has an execution witness;
a falsified exists-trace lemma means the requested execution is unreachable.
Timeouts remain inconclusive. These results depend on model assumptions.

Results and tool caches are ignored by Git. Reports can include local absolute
paths, command lines, model contents and trace values; review generated evidence
before sharing it separately.

The CI workflow bootstraps the pinned tools, runs runner tests, proves the
synthetic contracts and checks the mutation experiment. Its hosted execution
has not been validated as part of this local distribution.

Local validation covers 27 unit tests, both synthetic proof contracts, and the
independent signature-check mutation. Reproduce these checks with the commands
above; generated reports are kept locally.
