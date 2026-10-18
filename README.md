# DriftCert

Implementation of **Selective reauthorization by semantic refinement of evolving tool contracts**.

## Installation

Requires Python `>=3.11`. Run from the repository root in an activated environment.

```bash
python -m pip install -e .
```

Inspection environment: Python 3.13.5; numpy 2.1.3, matplotlib 3.10.0. Checks: Python syntax, configuration parsing and CLI/source argument matching. Training and full evaluation were not run.

## Data

The seeded generator constructs finite scenarios from the formal problem. Independently generated or recorded cases may be imported with the same JSONL schema.

The bundled generator writes synthetic finite-model scenarios as JSONL. Fix the seed and keep the generated input for paired comparisons.

```bash
python -m driftcert prepare --count 200 --seed 17 --output data/generated.jsonl
```

## Execution and evaluation

```bash
python -m driftcert run --data data/generated.jsonl --output runs/main
```

## Comparisons and ablations

```bash
python -m driftcert suite --data data/generated.jsonl --output runs/comparison
```

Use `--methods` to select: `driftcert`, `pin`, `schema`, `global`, `per_call`, `no_default_expansion`, `no_version_binding`, `no_gateway`.

## Outputs

`runs/main/driftcert/records.jsonl` stores per-case results; `metrics.json` stores aggregate measurements. Comparison outputs use one directory per method.

```bash
python -m driftcert plot --inputs runs/comparison/driftcert --output figures
```

Plotting writes `figures/summary.csv` and metric PNGs. Statistical intervals can be computed from a retained record file:

```bash
python -m driftcert.statistics --records runs/main/driftcert/records.jsonl --output results/intervals.json
```
