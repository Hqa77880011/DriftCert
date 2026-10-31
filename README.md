# DriftCert implementation

Implementation of **Selective reauthorization by semantic refinement of evolving tool contracts**.

The existing finite-model algorithms are retained. This revision adds typed old-precondition preservation in per-call and compiled paths, supported-domain enforcement, independent ordered-prefix refinement checking, correct old-consent-call denominators, and separated compilation/runtime costs. These are implementation and functional-validation artifacts; they are not the raw experimental code or evidence behind the manuscript's reported numbers.

## Installation

Requires Python >=3.11. From the repository root in an activated environment:

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

Installed validation environment: Windows, Python 3.13.5, numpy 2.1.3, scipy 1.15.3, matplotlib 3.10.0, psutil 7.1.0. Existing CI installs dependencies and runs the regression checks on Python 3.11.

## Data

The bundled generator produces synthetic finite-model scenarios for functional checks. It does not download a native benchmark, reproduce manuscript result tables or fit any parameters. Retain one generated input for paired comparisons:

```bash
python -m driftcert prepare --count 6 --seed 17 --output data/generated.jsonl
```

Each UTF-8 JSONL line has a unique `id`, optional `family`, and `cluster` identifying the actual independent policy/history family. The generator records `generation_seed` and conservatively clusters repeated examples by family. Imported independent data should supply its reviewed cluster IDs. Input fields are:

`old`: defaults, typed `requires` and ordered `allowed` effect rules; `new`: defaults and guarded `effects`; `mapping`: reviewed new-to-old argument names; `domains`: finite raw inputs with `__MISSING__` presence marker; `query`, `bound_version`, `current_version`, `base_permit`. Optional `runtime_trace` models a gateway effect that differs from the summary.

`core.generate` is an executable complete schema example. Use the same schema for reviewed recorded cases; keep native, mutation-derived and synthetic strata separate. No private data, manuscript, pretrained weights or original server logs are distributed. The algorithms use explicit policy/configuration inputs rather than learned models, and do not tune on test labels.

## Execution

```bash
python -m driftcert run --data data/generated.jsonl --output runs/main
```

## Evaluation

```bash
python -m driftcert evaluate --records runs/main/driftcert/records.jsonl --output runs/evaluated.json
```

`unsafe_reuse` counts committed unsafe old-consent calls/all old-consent reuse calls, including those blocked before commitment; no-reuse methods retain an undefined denominator. `safe_recall` conditions on supported oracle-safe, version-bound, base-permitted calls. `reconsent_precision` conditions on prompted calls; `prompt_rate` and `completion` use all calls. Ordered allowed traces are prefix-closed, so an empty prefix does not imply that mandatory earlier effects can be skipped before a later effect.

Rates are fractions in [0,1]. `null` means an inapplicable or unresolved denominator, not zero failures. `metrics.json` gives conditional per-case means, SD and quantiles; rate fields with explicit `metric_counts` also contain pooled `micro` numerator/denominator/rate. Whole-case `latency_ms` includes local construction and audits; stage metrics identify the narrower compilation/runtime path. `rss_mib` is a sampled resident value, not a measured peak. Throughput is local finite-model useful effects per whole-case wall second, not the manuscript's server throughput.

The same `evaluate` command accepts independently recorded JSONL with `id`, `method`, `cluster`, numerical-or-null `metrics`, and optional `metric_counts` mapping each rate name to `[numerator, denominator]`. Thus backend-only paper measurements can be aggregated when genuinely collected; missing lock waits, network latency, maintenance, attacker recovery or native task outcomes are not assigned invented values.

## Comparisons and ablations

```bash
python -m driftcert suite --data data/generated.jsonl --output runs/comparison
python -m driftcert.statistics --records runs/comparison/driftcert/records.jsonl --reference runs/comparison/per_call/records.jsonl --resamples 10000 --seed 17 --primary unsafe_reuse --output runs/paired.json
```

Select a subset with `--methods`. Implemented configurations: `driftcert`, `pin`, `schema`, `global`, `per_call`, `no_default_expansion`, `no_version_binding`, `no_gateway`. Deliberately lossy, unbound, feasibility-disabled and race variants are sandbox diagnostic controls, not safe deployments. The comparison implementations use this repository's declared finite semantics; they are not unmodified upstream systems.

Statistics first aggregate within each independent family and then bootstrap whole families. Paired analysis requires identical case IDs and excludes metrics undefined on either side. One eligible family yields no bootstrap interval. The zero-event bound concerns an event in an independent eligible cluster, not an iid per-request rate. McNemar is used only for independent single-record binary pairs; other paired summaries use Wilcoxon. Holm correction applies only to explicitly selected `--primary` endpoints. Small synthetic examples are not a source of experimental confidence intervals.

## Outputs and visualizations

```bash
python -m driftcert plot --inputs runs/comparison/driftcert runs/comparison/per_call --metrics unsafe_reuse latency_ms --output runs/figures
```

Each method directory contains `records.jsonl` (actual outcomes and conditional metrics), `metrics.json`, and `config.json` (command, environment and seeds). Plotting writes `summary.csv` plus selected metric PNGs; undefined metrics produce no misleading empty plot. All paths are configurable. Choose fresh output directories for reruns; generation/evaluation do not silently overwrite retained inputs or records.

## Paper-to-code map

| Paper module or metric | Code entry | Configuration / command |
|---|---|---|
| Dual-version presence/default interpretation | `core.normalized / effects` | old / new defaults; reviewed mapping |
| Finite guard and independent admission | `core.compile_guard; oracle.safe` | driftcert; domains |
| Ordered effect-prefix language | `core.refines; oracle.safe` | old.allowed; action/object/recipient/label |
| Current bindings and gateway summary agreement | `core.run_case` | versions; base_permit; runtime_trace |
| Reuse, recall, consent and upgrade/runtime metrics | `core.score` | evaluate; pin / schema / global / per_call |
| Aggregation, paired intervals and visualization | `cli.summarize; statistics.analyze; cli.plot` | evaluate / statistics / plot |

## Validation and implementation scope

Validated locally: editable installation, syntax/import and regression checks, six seed-17 cases through every suite configuration, retained-record re-evaluation, 10,000-resample paired analysis, selected metric PNG/CSV output, and wheel/source-distribution builds. No full paper campaign was run. Local functional records are retained under `runs/smoke/` (Git-ignored).

Regression checks cover hand-computable rates and eligible denominators, the algorithm's safety boundary, and applicable replay/serialization paths. The documented small-data preparation, execution, suite, evaluation, statistics and plotting commands are the validation entry points. No complete training or large experimental campaign is required for these checks.

Guarded effects use the same typed presence semantics as the independent checker:
missing differs from explicit null, and Boolean values differ from integers.
Gateway summary agreement compares canonical JSON, preserving these distinctions
inside nested effect records. Both boundaries have regression cases.

Guard compilation exhaustively enumerates concrete finite inputs; it does not implement symbolic counterexample-prioritized cell partitioning or the paper Uniform/Renew interaction baselines. Runtime traces are supplied finite observations, not an OS-level network/filesystem effect gateway. Consent renewal, approval expiry and reviewed native version-pair corpora require application adapters. Agent inference/token cost is not generated or inferred. Family-level statistics and micro counts are kept distinct.

The source retains its existing MIT license. Data and external systems remain subject to their own licenses and access rules.
