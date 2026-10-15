# DriftCert

Implementation of **Selective reauthorization by semantic refinement of evolving tool contracts**.

Implements separate old/new default expansion, reviewed field mapping, ordered effect refinement, finite safe-region compilation, bound reuse and pre-effect mediation.

## Install

Use Python 3.11 or newer.

```bash
git clone https://github.com/Hqa77880011/DriftCert.git
cd DriftCert
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS or `.venv\Scripts\Activate.ps1` in PowerShell.

```bash
python -m pip install -e .
```

## Prepare the workload

```bash
python -m driftcert prepare --count 200 --seed 17 --output data/workload.jsonl
```

The seeded generator constructs finite scenarios from the formal problem. Independently generated or recorded cases may be imported with the same JSONL schema.

`old` defines defaults, preconditions and the ordered approved effect language. `new` defines defaults and guarded effect records. Effects carry action, object set, canonical recipient and disclosure label. `domains` bounds new inputs; `mapping` maps new field names to old fields. Optional allowed transitions may be skipped; mandatory prerequisites cannot.

## Execute and compare

```bash
python -m driftcert run --data data/workload.jsonl --output runs/main
python -m driftcert suite --data data/workload.jsonl --output runs/comparison
```

`--methods` selects one or more method names. There are no learned parameters or model training in these finite algorithms.

`driftcert` uses the compiled guard; `pin` always requests new consent; `schema` reuses by schema compatibility; `global` reuses only when the entire domain refines; `per_call` checks concrete refinement. Ablations omit default expansion, version binding or the gateway.

## Metrics and plots

Unsafe reuse conditional on committed reuse, recall on safe inputs, prompt rate, completion, guard/certificate size and measured runtime.

Each method writes `records.jsonl` and `metrics.json` under its output subdirectory. Conditional rates omit cases outside their denominator. Summary fields include means, sample standard deviations, P50/P95/P99 and usable sample counts. Independent scoring runs after the method timer. RSS includes the process runtime; serialized sizes measure JSON bytes.

```bash
python -m driftcert plot --inputs runs/comparison/driftcert --output figures
```

Supply multiple method directories after `--inputs` for comparison. Plotting writes `summary.csv` and metric PNGs.

## Implementation conventions

Finite exhaustive guards replace SMT/BDD synthesis. Labels use explicit allowed sets, with a supplied lattice closure represented by those sets. Prefix closure allows an effect trace to stop before all possible transitions. The effect interpreter constructs all tool effects before mediation; a production tool must route its actual effects through the same gateway.


## Uncertainty and paired comparisons

```bash
python -m driftcert.statistics --records runs/main/driftcert/records.jsonl --output results/intervals.json
```

Supply --reference with a matched record file for paired differences. Resampling uses independent case IDs, or explicit cluster IDs when provided. Repeated observations from one source unit must share cluster. Zero-event bounds refer to an event in an independent cluster.
