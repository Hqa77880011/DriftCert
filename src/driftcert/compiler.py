"""Counterexample-directed safe cells, independent rechecking, and DNF/BDD guards."""

import copy
import heapq
import itertools
import math
import time

import z3

from . import semantics as sem
from .symbolic import Model


def predicates(domains):
    """Build the shared finite enumeration/presence/bound/scope predicate grammar."""
    result = []
    for name, values in sorted(domains.items()):
        choices = [{index} for index in range(len(values))]
        choices.append(
            {
                index
                for index, value in enumerate(values)
                if not sem.equal(value, sem.MISSING)
            }
        )
        for threshold in sorted(
            {value for value in values if type(value) in (int, float)}
        ):
            choices.append(
                {
                    index
                    for index, value in enumerate(values)
                    if type(value) in (int, float) and value <= threshold
                }
            )
        members = {
            sem.encode(item): item
            for value in values
            if isinstance(value, list)
            for item in value
        }
        for member in members.values():
            choices.append(
                {
                    index
                    for index, value in enumerate(values)
                    if isinstance(value, list)
                    and any(sem.equal(item, member) for item in value)
                }
            )
        for selected in sorted(
            {
                tuple(sorted(choice))
                for choice in choices
                if choice and len(choice) < len(values)
            }
        ):
            result.append(dict(field=name, indices=list(selected)))
    return result


def volume(cell):
    return math.prod(len(indices) for indices in cell.values())


def _influencers(case):
    names = set()

    def visit(item):
        if isinstance(item, str) and item.startswith("$"):
            names.add("@state." + item[7:] if item.startswith("$state.") else item[1:])
        elif isinstance(item, list):
            for value in item:
                visit(value)
        elif isinstance(item, dict):
            for key, value in item.items():
                if (
                    key in ("when", "requires")
                    and isinstance(value, dict)
                    and not set(value) & {"all", "any", "not", "compare", "present"}
                ):
                    names.update(value)
                visit(value)

    visit(case["new"])
    names.update(sem.old_parameters(case))
    return names


def split(cell, predicate):
    name = predicate["field"]
    selected = set(predicate["indices"])
    yes = [index for index in cell[name] if index in selected]
    no = [index for index in cell[name] if index not in selected]
    return ({**cell, name: yes}, {**cell, name: no}) if yes and no else None


def _mass(cell, case, domains):
    weights = case.get("development_weights", {})
    value = 1.0
    for name, indices in cell.items():
        field = weights.get(name)
        value *= (
            sum(field.get(sem.encode(domains[name][index]), 0) for index in indices)
            if field
            else len(indices) / len(domains[name])
        )
    return value


def build_bdd(cells, grammar, domains):
    """Build a reduced ordered BDD by cached Boolean apply, without point expansion."""
    nodes = {}
    unique = {}
    memo = {}

    def make(predicate, low, high):
        if low == high:
            return low
        key = (predicate, low, high)
        if key not in unique:
            identifier = len(nodes) + 2
            unique[key] = identifier
            nodes[str(identifier)] = dict(predicate=predicate, low=low, high=high)
        return unique[key]

    def apply(operation, left, right):
        left, right = sorted((left, right))
        key = (operation, left, right)
        if key in memo:
            return memo[key]
        if left < 2 and right < 2:
            return int(left and right) if operation == "and" else int(left or right)
        if operation == "and":
            if left == 0:
                return 0
            if left == 1:
                return right
        else:
            if left == 0:
                return right
            if left == 1:
                return 1
        if left == right:
            return left
        lnode = nodes[str(left)]
        rnode = nodes[str(right)]
        variable = min(lnode["predicate"], rnode["predicate"])
        low = apply(
            operation,
            lnode["low"] if lnode["predicate"] == variable else left,
            rnode["low"] if rnode["predicate"] == variable else right,
        )
        high = apply(
            operation,
            lnode["high"] if lnode["predicate"] == variable else left,
            rnode["high"] if rnode["predicate"] == variable else right,
        )
        memo[key] = make(variable, low, high)
        return memo[key]

    exact = {
        (predicate["field"], tuple(predicate["indices"])): index
        for index, predicate in enumerate(grammar)
    }
    root = 0
    for cell in cells:
        region = 1
        for name, indices in cell.items():
            if len(indices) == len(domains[name]):
                continue
            if (name, tuple(indices)) in exact:
                test = make(exact[name, tuple(indices)], 0, 1)
            else:
                test = 0
                for index in indices:
                    test = apply("or", test, make(exact[name, (index,)], 0, 1))
            region = apply("and", region, test)
        root = apply("or", root, region)
    return dict(root=root, nodes=nodes)


def bdd_formula(model, bdd, grammar):
    memo = {0: z3.BoolVal(False), 1: z3.BoolVal(True)}

    def visit(identifier):
        if identifier not in memo:
            node = bdd["nodes"][str(identifier)]
            predicate = grammar[node["predicate"]]
            test = z3.Or(
                *(
                    model.variables[predicate["field"]] == index
                    for index in predicate["indices"]
                )
            )
            memo[identifier] = z3.If(test, visit(node["high"]), visit(node["low"]))
        return memo[identifier]

    return visit(bdd["root"])


def compile_guard(case, method="driftcert"):
    """Certify safe cells; SAT witnesses and UNKNOWN cells remain separate."""
    case = sem.canonical_case(case)
    stamp = time.perf_counter()
    deadline = stamp + case.get("compile_budget_seconds", 60)
    frozen_keys = {
        "old",
        "new",
        "domains",
        "mapping",
        "state",
        "state_domains",
        "recipient_aliases",
        "label_order",
        "integer_bits",
        "bindings",
        "set_fields",
        "old_version",
        "new_version",
    }
    frozen = {
        key: copy.deepcopy(value) for key, value in case.items() if key in frozen_keys
    }
    analysis = copy.deepcopy(frozen)
    if method == "no_default_expansion":
        analysis["new"]["defaults"] = copy.deepcopy(case["old"].get("defaults", {}))
    model = Model(analysis)
    grammar = predicates(model.domains)
    search_grammar = grammar[: case.get("predicate_budget", len(grammar))]
    top = {name: list(range(len(values))) for name, values in model.domains.items()}
    safe, unsafe, unresolved = [], [], []
    queries = 0
    checker_queries = 0
    serial = itertools.count()
    queue = []
    heapq.heappush(queue, (-_mass(top, case, model.domains), next(serial), top))
    influences = _influencers(case)
    solver_ms = case.get("solver_timeout_ms", 1000)
    while (
        queue
        and queries < case.get("cell_budget", 10000)
        and time.perf_counter() < deadline
    ):
        _, _, cell = heapq.heappop(queue)
        remaining = max(1, min(solver_ms, (deadline - time.perf_counter()) * 1000))
        answer = model.query(cell, timeout_ms=remaining)
        queries += 1
        if answer["status"] == "UNSAT":
            checker_queries += method != "no_checker"
            verification = (
                model.query(
                    cell,
                    independent=True,
                    timeout_ms=max(
                        1, min(solver_ms, (deadline - time.perf_counter()) * 1000)
                    ),
                )
                if method != "no_checker"
                else dict(status="DISABLED")
            )
            if verification["status"] in ("UNSAT", "DISABLED"):
                safe.append(cell)
            else:
                unresolved.append(
                    dict(
                        cell=cell,
                        reason="checker_" + verification["status"].lower(),
                        witness=verification.get("raw"),
                    )
                )
        elif answer["status"] == "UNKNOWN":
            unresolved.append(dict(cell=cell, reason="solver_unknown"))
        else:
            try:
                delta = sem.failure(analysis, answer["raw"], answer["state"])
            except KeyError:
                delta = dict(
                    reason="undefined_old_effect_reference", fields=[], guards=[]
                )
            unsafe.append(
                dict(
                    raw=answer["raw"],
                    state=answer["state"],
                    indices=answer["indices"],
                    delta=delta,
                )
            )
            candidates = [
                (predicate, split(cell, predicate))
                for predicate in search_grammar
                if split(cell, predicate)
            ]
            if not candidates:
                if volume(cell) > 1:
                    unresolved.append(dict(cell=cell, reason="grammar_exhausted"))
                continue
            if method == "global":
                continue
            if method == "uniform":
                predicate, children = candidates[0]
            else:

                def score(candidate):
                    predicate, children = candidate
                    witness_side = (
                        answer["indices"][predicate["field"]] in predicate["indices"]
                    )
                    other = children[1 if witness_side else 0]
                    return (
                        predicate["field"] in delta["fields"],
                        predicate["field"] in delta["guards"],
                        predicate["field"] in influences,
                        _mass(other, case, model.domains),
                        -len(predicate["indices"]),
                    )

                predicate, children = max(candidates, key=score)
            for child in children:
                priority = (
                    next(serial)
                    if method == "uniform"
                    else -_mass(child, case, model.domains)
                )
                heapq.heappush(queue, (priority, next(serial), child))
    unresolved += [dict(cell=cell, reason="compile_budget") for _, _, cell in queue]
    if case.get("guard_fault"):
        corrupted = copy.deepcopy(safe[0]) if safe else copy.deepcopy(top)
        field = next(iter(corrupted), None)
        if field:
            corrupted[field] = list(top[field])
        verification = (
            model.query(corrupted, independent=True, timeout_ms=solver_ms)
            if method != "no_checker"
            else dict(status="DISABLED")
        )
        if verification["status"] in ("UNSAT", "DISABLED"):
            safe.append(corrupted)
        else:
            unresolved.append(dict(cell=corrupted, reason="seeded_defect_rejected"))
    bdd = build_bdd(safe, grammar, model.domains)
    equivalence = z3.Solver()
    equivalence.set(timeout=solver_ms)
    dnf = z3.Or(*(model.cell_formula(cell) for cell in safe))
    equivalence.add(model.domain, z3.Xor(dnf, bdd_formula(model, bdd, grammar)))
    conversion = equivalence.check()
    if conversion == z3.sat:
        raise RuntimeError("DNF/BDD conversion counterexample")
    representation = "bdd" if conversion == z3.unsat else "dnf"
    return dict(
        format=1,
        method=method,
        case=frozen,
        analysis=analysis,
        representation=representation,
        domains=model.domains,
        predicates=grammar,
        cells=safe,
        bdd=bdd,
        unsafe_witnesses=unsafe,
        unresolved=unresolved,
        queries=queries,
        synthesis_queries=queries,
        checker_queries=checker_queries,
        search_predicates=len(search_grammar),
        compilation_ms=(time.perf_counter() - stamp) * 1000,
        checker="disabled_diagnostic"
        if method == "no_checker"
        else "independent_transition_matching",
        conversion="equivalent_over_declared_new_domain"
        if conversion == z3.unsat
        else "unknown_retained_checked_dnf",
    )


def indices(package, raw, state=None):
    state = state or {}
    raw = sem.canonical_raw(package["case"], raw)
    if set(raw) - set(package["case"]["domains"]):
        return None
    result = {}
    for name, values in package["domains"].items():
        actual = (
            state.get(name[7:], sem.MISSING)
            if name.startswith("@state.")
            else raw.get(name, sem.MISSING)
        )
        if name in raw and sem.equal(actual, sem.MISSING):
            return None
        match = next(
            (index for index, value in enumerate(values) if sem.equal(value, actual)),
            None,
        )
        if match is None:
            return None
        result[name] = match
    for name, value in package["case"].get("state", {}).items():
        if "@state." + name not in package["domains"] and (
            name not in state or not sem.equal(state[name], value)
        ):
            return None
    return result


def accepts(package, raw, state=None, representation="bdd"):
    """Evaluate only frozen predicates, retaining raw presence and current state."""
    raw = sem.canonical_raw(package["case"], raw)
    point = indices(package, raw, state)
    if point is None or not sem.valid_new(package["case"], raw, state):
        return False
    if representation == "dnf" or package.get("representation") == "dnf":
        return any(
            all(point[name] in allowed for name, allowed in cell.items())
            for cell in package["cells"]
        )
    identifier = package["bdd"]["root"]
    while identifier > 1:
        node = package["bdd"]["nodes"][str(identifier)]
        predicate = package["predicates"][node["predicate"]]
        identifier = (
            node["high"]
            if point[predicate["field"]] in predicate["indices"]
            else node["low"]
        )
    return identifier == 1
