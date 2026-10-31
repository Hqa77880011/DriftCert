"""Repeated-call amortization, adaptive boundary probing and exact pair coverage."""

import copy
import itertools
import random
import time

import psutil
import z3

from . import compiler, core
from . import semantics as sem
from .oracle import safe
from .symbolic import Model


def benchmark(
    case, method, calls=100, restarts=1, warmup_seconds=0, measurement_seconds=0
):
    """Measure actual upgrade and repeated authorization costs; no generated timings."""
    if restarts > 1:
        import multiprocessing

        context = multiprocessing.get_context("spawn")
        rows = []
        for restart in range(restarts):
            parent, child = context.Pipe(False)
            process = context.Process(
                target=_benchmark_worker,
                args=(child, case, method, calls, warmup_seconds, measurement_seconds),
            )
            process.start()
            child.close()
            try:
                row = parent.recv()
            except EOFError as error:
                process.join()
                raise RuntimeError(
                    "Benchmark worker exited without a result"
                ) from error
            process.join()
            if process.exitcode != 0:
                raise RuntimeError("Benchmark worker failed")
            if "error" in row:
                raise RuntimeError(row["error"])
            row["id"] = str(restart)
            row["protocol"]["restart"] = restart
            rows.append(row)
        return rows
    rows = []
    for restart in range(restarts):
        cpu = time.process_time()
        wall = time.perf_counter()
        package = core.prepare(case, method)
        upgrade_cpu = time.process_time() - cpu
        upgrade_wall = time.perf_counter() - wall
        finish = time.perf_counter() + warmup_seconds
        while time.perf_counter() < finish:
            core.run_case(case, method, package)
        online_cpu = time.process_time()
        online_wall = time.perf_counter()
        latencies = []
        completed = 0
        receipts = 0
        finish = online_wall + measurement_seconds
        while completed < calls or time.perf_counter() < finish:
            stamp = time.perf_counter()
            result = core.run_case(case, method, package)
            latencies.append((time.perf_counter() - stamp) * 1000)
            receipts += result["committed"]
            completed += 1
        duration = time.perf_counter() - online_wall
        rows.append(
            dict(
                id=str(restart),
                method=method,
                cluster=case.get("family", case["id"]),
                metrics=dict(
                    upgrade_cpu_seconds=upgrade_cpu,
                    upgrade_wall_seconds=upgrade_wall,
                    online_cpu_seconds=time.process_time() - online_cpu,
                    online_wall_seconds=duration,
                    calls=completed,
                    completed=receipts,
                    throughput=completed / duration,
                    total_cpu_seconds=time.process_time() - cpu,
                    rss_mib=psutil.Process().memory_info().rss / 2**20,
                    p50_ms=quantile(latencies, 0.5),
                    p95_ms=quantile(latencies, 0.95),
                    p99_ms=quantile(latencies, 0.99),
                ),
                protocol=dict(
                    restart=restart,
                    warmup_seconds=warmup_seconds,
                    measurement_seconds=measurement_seconds,
                ),
            )
        )
    return rows


def quantile(values, q):
    values = sorted(values)
    index = (len(values) - 1) * q
    low = int(index)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (index - low)


def exact_regions(case, method):
    """Only the validation oracle enumerates the full finite input/state space."""
    package = core.prepare(case, method)
    states = (
        list(core.universe(case.get("state_domains", {})))
        if case.get("state_domains")
        else [case.get("state", {})]
    )
    counts = dict(
        true_safe=0, false_safe=0, false_unsafe=0, true_unsafe=0, unsupported=0
    )
    for raw, state in itertools.product(core.universe(case["domains"]), states):
        if not sem.valid_new(case, raw, state):
            counts["unsupported"] += 1
            continue
        point = {**case, "query": raw, "query_state": state}
        result = core.run_case(point, method, package)
        label = safe(case, raw, state)
        counts[
            ("true_safe" if label else "false_safe")
            if result["reuse"]
            else ("false_unsafe" if label else "true_unsafe")
        ] += 1
    return counts


def attack(case, package, visibility="black", budget=100, seed=17):
    """Keep each observed attempt; white-box solves the actual frozen g AND B."""
    rng = random.Random(seed)
    model = Model(case)
    rows = []
    solver = None
    if visibility == "white":
        solver = z3.Solver()
        solver.set(timeout=case.get("solver_timeout_ms", 1000))
        solver.add(
            model.domain,
            model.independent_bad,
            z3.Or(*(model.cell_formula(cell) for cell in package["cells"])),
        )
    last = None
    for index in range(budget):
        status = None
        if solver is not None:
            status = solver.check()
            if status != z3.sat:
                rows.append(dict(attempt=index, status=str(status), raw=None))
                break
            values = {
                name: solver.model().eval(variable, model_completion=True).as_long()
                for name, variable in model.variables.items()
            }
            raw = {
                name: copy.deepcopy(model.domains[name][value])
                for name, value in values.items()
                if not name.startswith("@state.")
                and not sem.equal(model.domains[name][value], sem.MISSING)
            }
            state = {
                **case.get("state", {}),
                **{
                    name[7:]: model.domains[name][value]
                    for name, value in values.items()
                    if name.startswith("@state.")
                },
            }
            solver.add(
                z3.Or(
                    *(model.variables[name] != value for name, value in values.items())
                )
            )
        else:
            raw = (
                copy.deepcopy(last) if visibility == "gray" and last is not None else {}
            )
            names = list(case["domains"])
            selected = [rng.choice(names)] if raw else names
            for name in selected:
                value = rng.choice(case["domains"][name])
                if sem.equal(value, sem.MISSING):
                    raw.pop(name, None)
                else:
                    raw[name] = copy.deepcopy(value)
            state = case.get("state", {})
        accepted = compiler.accepts(package, raw, state)
        label = safe(case, raw, state) if sem.valid_new(case, raw, state) else None
        rows.append(
            dict(
                attempt=index,
                status="observed",
                raw=raw,
                state=state,
                accepted=accepted,
                oracle_safe=label,
                violation=accepted and label is False,
            )
        )
        if visibility == "gray":
            last = raw if accepted else None
    return rows


def sweep(
    case,
    budgets=(1, 10, 60, 300),
    predicate_counts=(4, 8, 12, 16),
    effect_lengths=(1, 2, 4, 8),
):
    """Emit executable sensitivity configurations; callers select the CPU budget."""
    for budget, cells, length in itertools.product(
        budgets, predicate_counts, effect_lengths
    ):
        item = copy.deepcopy(case)
        item.update(compile_budget_seconds=budget, predicate_budget=cells)
        # Repeated optional audit transitions preserve declared order and task semantics.
        for contract, key in ((item["old"], "allowed"), (item["new"], "effects")):
            branch = contract[key]
            audit = copy.deepcopy(branch[0])
            contract[key] = [copy.deepcopy(audit) for _ in range(length - 1)] + branch
        yield dict(id=f"{case['id']}:{budget}:{cells}:{length}", case=item)


def _benchmark_worker(connection, case, method, calls, warmup, measurement):
    try:
        connection.send(benchmark(case, method, calls, 1, warmup, measurement)[0])
    except (ValueError, RuntimeError, KeyError) as error:
        connection.send({"error": str(error)})
    finally:
        connection.close()
