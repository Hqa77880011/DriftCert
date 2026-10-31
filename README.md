# DriftCert implementation

Implementation of **Selective reauthorization by semantic refinement of evolving tool contracts**.

The implementation now includes symbolic counterexample-directed cell synthesis, independent transition-matching verification, frozen DNF/reduced-BDD guards, all six manuscript comparison mechanisms and four distinct component-removal diagnostics. A signed approval ledger and restricted JSON effect interpreter perform real protected-file reads, audit writes and exports. The executable bounded IR and local validations do not supply the manuscript's original native corpus or reported numerical results.

## Installation

Requires Python >=3.11. From the repository root in an activated environment:

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

Installed validation environment: Windows, Python 3.13.5, numpy 2.1.3, scipy 1.15.3, matplotlib 3.10.0, psutil 7.1.0 and project-local Z3. Existing CI installs dependencies and runs the regression checks on Python 3.11.

## Data

The bundled generator produces synthetic finite-model scenarios for functional checks. It does not download a native benchmark, reproduce manuscript result tables or fit any parameters. Retain one generated input for paired comparisons:

```bash
python -m driftcert prepare --count 6 --seed 17 --output data/generated.jsonl
```

Each UTF-8 JSONL line has a unique `id`, optional `family`, and `cluster` identifying the actual independent policy/history family. The generator records `generation_seed` and conservatively clusters repeated examples by family. Imported independent data should supply its reviewed cluster IDs. Input fields are:

`old`: defaults, parameters, typed preconditions and ordered `allowed` (or multiple `traces`) effect rules; `new`: defaults, preconditions and guarded `effects` (or multiple summary `traces`). `mapping` is the reviewed partial new-to-old parameter map; `__DROP__` is an explicit reviewed discard. Undefined destinations and collisions prohibit reuse. `domains` and optional `state_domains` declare finite typed values; `__MISSING__` is reserved for absent raw fields and differs from null, false and zero. `state` fixes reviewed state assumptions; `query_state` supplies live values. Integer arithmetic is bounded to signed `integer_bits` (default 64).

Expressions support `$parameter`, `$raw.parameter`, `$state.field`, conditional values and finite set union/intersection/difference. Conditions support all/any/not/present and typed eq/ne/lt/le/gt/ge/subset/contains. Recipient aliases are canonicalized; `label_order` defines the security lattice's directed edges. Summary branches universally overapproximate behavior. Old languages existentially choose a trace and preserve required predecessor order; optional and inactive transitions may be skipped. Unknown external behavior is outside this reviewed IR and requires reapproval.

`query`, `bound_version`, `current_version`, and `base_permit` drive recorded-model evaluation. Optional `runtime_trace` and `current_new` are explicitly observed/injected behavior, not OS mediation. `fresh_approval` records an explicit approved principal/version/expiry/task `contract`; absent consent remains a prompt. `approval_valid`, `approval_revoked`, `approval_expires`, `now`, and optional exact `bindings` cover the recorded approval lifecycle. Actual signed records and live I/O use `gateway.py` rather than these evaluation labels.

`core.generate` is an executable complete schema example. Use the same schema for reviewed recorded cases; keep native, mutation-derived and synthetic strata separate. No private data, manuscript, pretrained weights or original server logs are distributed. The algorithms use explicit policy/configuration inputs rather than learned models, and do not tune on test labels.

## Execution

```bash
python -m driftcert run --data data/generated.jsonl --output runs/main
```

## Evaluation

```bash
python -m driftcert evaluate --records runs/main/driftcert/records.jsonl --output runs/evaluated.json
```

`unsafe_reuse` counts committed unsafe old-consent calls/all old-consent reuse calls, including those blocked before commitment; no-reuse methods retain an undefined denominator. `safe_recall` conditions on supported oracle-safe, base-permitted calls with valid old approval. A version/package mismatch is also retained as `binding_violation`; it is not automatically an effect outside the old contract. `reconsent_precision` conditions on prompted calls; `prompt_rate` and `completion` use all calls. Ordered allowed traces are prefix-closed, so an empty prefix does not imply that mandatory earlier effects can be skipped before a later effect.

Rates are fractions in [0,1]. `null` means an inapplicable or unresolved denominator, not zero failures. `metrics.json` gives conditional per-case means, SD and quantiles; rate fields with explicit `metric_counts` also contain pooled `micro` numerator/denominator/rate. Whole-case `latency_ms` includes local construction and audits; stage metrics identify the narrower compilation/runtime path. `rss_mib` is a sampled resident value, not a measured peak. Throughput is local finite-model useful effects per whole-case wall second, not the manuscript's server throughput.

The same `evaluate` command accepts independently recorded JSONL with `id`, `method`, `cluster`, numerical-or-null `metrics`, and optional `metric_counts` mapping each rate name to `[numerator, denominator]`. Thus backend-only paper measurements can be aggregated when genuinely collected; missing lock waits, network latency, maintenance, attacker recovery or native task outcomes are not assigned invented values.

## Comparisons and ablations

```bash
python -m driftcert suite --data data/generated.jsonl --output runs/comparison
python -m driftcert.statistics --records runs/comparison/driftcert/records.jsonl --reference runs/comparison/per_call/records.jsonl --resamples 10000 --seed 17 --primary unsafe_reuse --output runs/paired.json
```

Select a subset with `--methods`. Implemented configurations: `driftcert`, `pin`, `schema`, `global`, `per_call`, `renew`, `uniform`, `no_default_expansion`, `no_version_binding`, `no_checker`, `no_gateway`.

- Full uses weighted counterexample-sensitive splits, then an independently encoded existential transition-matching checker. Synthesis uses a forward language automaton. Neither enumerates the full Cartesian input space. Finite enumeration is restricted to the independent validation command.
- Uniform uses the same grammar, solver, checker and declared budgets, with FIFO/fixed predicate subdivision. Global checks the entire domain once. SAT, checker disagreement, UNKNOWN, budget exhaustion and grammar exhaustion never become certified safe cells.
- PerCall rebuilds the full symbolic refinement decision for each invocation. Pin and Renew obtain explicit fresh task approval; they do not silently manufacture user consent. Schema checks a documented conservative JSON Schema fragment (type, properties, required, additionalProperties, enum, numeric bounds and items); it deliberately does not infer effects from input compatibility. Defaults remain annotations for this weak diagnostic.
- NoDefaults removes normalizer expansion in the analyzed semantics. NoChecker is meaningful with `guard_fault` seeded synthesis defects. NoGateway uses `runtime_trace` false-summary faults. NoVersionBinding removes exact binding checks. These variants are deliberate assumption violations and must run only in an isolated application root.

`development_weights` guide search only; query inputs, runtime traces and test labels are excluded from frozen packages. `compile_budget_seconds`, `solver_timeout_ms` and `cell_budget` are real limits. Conversion proves DNF/BDD equivalence over the declared typed domain; conversion UNKNOWN retains the independently checked DNF instead of claiming equivalence. Deliberately lossy, unbound, feasibility-disabled and race variants are sandbox diagnostic controls, not safe deployments. The comparison implementations use this repository's declared finite semantics; they are not unmodified upstream systems.

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

The symbolic and real-execution additions have separate direct entries:

```bash
# A single JSON case is one object from the JSONL corpus.
python -m driftcert compile --case case.json --method driftcert --output package.json
python -m driftcert query --package package.json --input request.json --representation bdd
python -m driftcert regions --case case.json --method uniform --output regions.json
python -m driftcert attack --case case.json --visibility white --budget 100 --output white.json
python -m driftcert benchmark --case case.json --method driftcert --calls 1000 --restarts 5 --warmup 30 --seconds 120 --output benchmark.json
```

`request.json` contains `raw` and optional `state`. Compiled packages survive JSON serialization without input enumeration at admission. `regions` enumerates independent oracle labels and confusion counts; `attack` retains every black-box random, gray-box guard-feedback or white-box `guard AND Bad` attempt and solver uncertainty. `evaluation.sweep` emits budget/cell/effect-length configurations for sensitivity campaigns. The benchmark compiles once per version pair, then measures repeated invocations; multiple restarts spawn fresh processes. Upgrade CPU/wall, online CPU/wall, latency quantiles, calls and RSS samples are measured directly. Short smoke timings are not full paper performance measurements. Family-cluster statistics remain applicable to independently recorded rows.

`gateway.Gateway(root, database, key, objects, sinks)` is the real local application adapter. The object registry maps IDs to application-owned paths and trusted labels; sinks map canonical recipients to directories. The restricted program is a list of `{"emit": effect}` or `{"if": condition, "then": nodes, "else": nodes}` nodes. It executes no arbitrary Python or shell code. Install the signed package with exact implementation version, principal and task; an optional `bindings.implementation_digest` binds the reviewed program. Explicit `approve` records expire and can be revoked. `set_acl` supplies current base authorization; `set_state` maintains application-owned live predicate values and in-flight commits reject changed snapshots; `advance_epoch` invalidates old packages. Every actual effect checks the approval, signature, current epoch/version/ACL, frozen guard and summary prefix before I/O. Renew/Pin use an explicit current task contract instead of old consent. Durable receipts include approval, epoch and actual effect. Already authorized prefix effects can commit before a later effect is denied. SQLite and filesystem writes are not claimed to be one crash-atomic distributed transaction.

The `native` CLI loads an application-owned JSON config (`root`, `database`, `key_file`, `objects`, `sinks`) and an explicit JSON operation request (`action`: install/approve/revoke/advance_epoch/set_acl/execute plus method arguments). It writes the actual response; the key is read from the indicated local file and is never printed. Production callers must pass authenticated identities and the installed implementation version, and must not expose diagnostic method selection. No general OS sandbox is claimed.

Local validation covers 21 tests, including independent finite oracle vs both symbolic encodings, all 11 matrix entries, typed missing/null/Boolean/integer boundaries, state, set canonicalization, signed-integer limits, aliases, lattice, nondeterministic summaries, seeded checker defects, DNF/BDD save/load, real protected-byte export, durable receipts, revoked/expired identities and epoch/current ACL enforcement, false-summary rejection and explicit renewed approval. Six generated change families pass the paired suite; retained artifacts are under `runs/published-v2/`. Two fresh-process short amortization runs, white-box checks, retained-record evaluation, 10,000 paired family resamples and PNG/CSV entries were also exercised. The original ContractDrift/native-review corpus, AgentDojo/ToolSandbox mutations, human review timings, model clients and full 16-core campaign are external evidence not present here; importer inputs retain their actual stratum and family IDs, and the implementation does not reproduce their published numbers.

The source retains its existing MIT license. Data and external systems remain subject to their own licenses and access rules.
