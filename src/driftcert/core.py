"""Compiled consent preservation and the manuscript's matched mechanism baselines."""

import itertools
import time

from . import compiler, schema
from . import semantics as sem
from .oracle import safe as reference_safe
from .symbolic import Model

METHODS = [
    "driftcert",
    "pin",
    "schema",
    "global",
    "per_call",
    "renew",
    "uniform",
    "no_default_expansion",
    "no_version_binding",
    "no_checker",
    "no_gateway",
]
normalized = sem.normalized


def effects(raw, contract, state=None):
    branches = sem.traces(raw, contract, state)
    if len(branches) != 1:
        raise ValueError(
            "Select an explicit execution branch for nondeterministic summaries"
        )
    return branches[0]


def refines(trace, contract, case=None, args=None, raw=None, state=None):
    return sem.refines(trace, contract, case, args, raw, state)


def universe(domains):
    keys = sorted(domains)
    for values in itertools.product(*(domains[key] for key in keys)):
        yield {
            key: value
            for key, value in zip(keys, values)
            if not sem.equal(value, sem.MISSING)
        }


def supported(raw, domains):
    return not set(raw) - set(domains) and all(
        any(sem.equal(raw.get(name, sem.MISSING), value) for value in values)
        for name, values in domains.items()
    )


def old_preconditions(case, raw, state=None):
    mapped = sem.mapped(case, raw)
    if mapped is None:
        return False
    args = sem.normalized(mapped, case["old"])
    return sem.condition(
        case["old"].get("requires", True), args, state, mapped
    ) and all(name in args for name in case["old"].get("required_parameters", []))


def compile_guard(case, method="driftcert"):
    return compiler.compile_guard(case, method)


def prepare(case, method):
    if method in ("pin", "renew", "schema", "per_call"):
        return None
    return compile_guard(case, method)


def generate(rng, count):
    for index in range(count):
        old = {
            "defaults": {"remote": False, "recipient": "local", "objects": ["public"]},
            "requires": {},
            "allowed": [
                {
                    "action": "audit",
                    "objects": ["public", "private"],
                    "recipients": ["local"],
                    "labels": ["public", "private"],
                },
                {
                    "action": "export",
                    "objects": ["public"],
                    "recipients": ["local"],
                    "labels": ["public"],
                },
            ],
        }
        new = {
            "defaults": {"remote": True, "recipient": "local", "objects": ["public"]},
            "effects": [
                {
                    "action": "audit",
                    "objects": "$objects",
                    "recipient": "local",
                    "label": "public",
                },
                {
                    "action": "export",
                    "objects": "$objects",
                    "recipient": "$recipient",
                    "label": "public",
                    "when": {"remote": False},
                },
                {
                    "action": "export",
                    "objects": "$objects",
                    "recipient": "remote",
                    "label": "public",
                    "when": {"remote": True},
                },
            ],
        }
        domains = {
            "remote": [False, True, "__MISSING__"],
            "recipient": ["local", "remote"],
            "objects": [["public"], ["public", "private"]],
        }
        families = [
            "default_widening",
            "recipient_widening",
            "selector_widening",
            "effect_addition",
            "precondition_weakening",
            "equivalent_refactor",
        ]
        family = families[index % len(families)]
        mapping = {}
        if family == "recipient_widening":
            new["defaults"]["remote"] = False
            old["allowed"][1]["objects"] = ["public", "private"]
        elif family == "selector_widening":
            new["defaults"]["remote"] = False
            domains["recipient"] = ["local"]
        elif family == "effect_addition":
            domains["extra"] = [False, True, "__MISSING__"]
            mapping["extra"] = "__DROP__"
            new["defaults"]["extra"] = False
            new["effects"].append(
                dict(
                    action="notify",
                    objects=["public"],
                    recipient="remote",
                    label="public",
                    when={"extra": True},
                )
            )
        elif family == "precondition_weakening":
            old["defaults"]["approved"] = True
            old["requires"] = {"approved": True}
            new["defaults"]["approved"] = False
            domains["approved"] = [False, True, "__MISSING__"]
        elif family == "equivalent_refactor":
            new["defaults"]["remote"] = False
            domains["remote"] = [False, "__MISSING__"]
            domains["dest"] = domains.pop("recipient")
            new["defaults"]["dest"] = new["defaults"].pop("recipient")
            mapping["dest"] = "recipient"
            for effect in new["effects"]:
                if effect["recipient"] == "$recipient":
                    effect["recipient"] = "$dest"
        query = rng.choice(list(universe(domains)))
        yield {
            "id": str(index),
            "family": family,
            "old": old,
            "new": new,
            "domains": domains,
            "mapping": mapping,
            "query": query,
            "bound_version": 1,
            "current_version": 2 if rng.random() < 0.15 else 1,
            "base_permit": rng.random() < 0.95,
        }


def run_case(case, method, package=None):
    case = sem.canonical_case(case)
    if method not in METHODS:
        raise ValueError(method)
    needs = method not in ("pin", "renew", "schema", "per_call")
    compiled_here = needs and package is None
    if compiled_here:
        package = prepare(case, method)
    start = time.perf_counter()
    raw, state = case["query"], case.get("query_state", case.get("state", {}))
    domain_ok = supported(raw, case["domains"]) and sem.valid_new(case, raw, state)
    domain_ok = domain_ok and all(
        name in case.get("state_domains", {})
        or name in state
        and sem.equal(state[name], value)
        for name, value in case.get("state", {}).items()
    )
    answer = None
    if method == "pin":
        reuse = (
            domain_ok
            and "old_version" in case
            and case["old_version"] == case.get("new_version")
        )
    elif method == "renew":
        reuse = False
    elif method == "schema":
        reuse = domain_ok and schema.compatible(case, raw)
    elif method == "per_call":
        model = Model(case)
        point = {}
        if domain_ok:
            for name, values in model.domains.items():
                actual = (
                    state.get(name[7:], sem.MISSING)
                    if name.startswith("@state.")
                    else raw.get(name, sem.MISSING)
                )
                index = next(
                    (
                        index
                        for index, value in enumerate(values)
                        if sem.equal(value, actual)
                    ),
                    None,
                )
                if index is None:
                    domain_ok = False
                    break
                point[name] = [index]
        if not domain_ok:
            point = None
        answer = (
            model.query(point, timeout_ms=case.get("solver_timeout_ms", 1000))
            if point is not None
            else {"status": "UNSUPPORTED"}
        )
        reuse = domain_ok and answer["status"] == "UNSAT"
    else:
        reuse = domain_ok and compiler.accepts(package, raw, state)
    bound = case.get("bound_version") == case.get("current_version")
    bound = bound and all(
        sem.equal(case.get("bound_" + key, value), case.get("current_" + key, value))
        for key, value in case.get("bindings", {}).items()
    )
    old_valid = (
        case.get("approval_valid", True)
        and not case.get("approval_revoked", False)
        and case.get("now", 0) < case.get("approval_expires", float("inf"))
    )
    reuse = bool(reuse and old_valid and (bound or method == "no_version_binding"))
    actual = case.get("current_new", case["new"])
    candidates = sem.traces(raw, actual, state) if domain_ok else [[]]
    trace = case.get("runtime_trace", candidates[case.get("branch", 0)])
    analyzed = sem.traces(raw, case["new"], state) if domain_ok else [[]]
    gateway = method == "no_gateway" or any(
        len(trace) <= len(branch)
        and all(sem.equal(a, b) for a, b in zip(trace, branch))
        for branch in analyzed
    )
    renewed = False
    fresh = case.get("fresh_approval")
    if not reuse and fresh and fresh.get("approved") is True:
        renewed = (
            fresh.get("version") == case.get("current_version")
            and fresh.get("principal") == case.get("principal", "fixture")
            and case.get("now", 0) < fresh.get("expires", 0)
            and not fresh.get("revoked", False)
            and sem.refines(
                trace, fresh["contract"], case, sem.normalized(raw, actual), raw, state
            )
        )
    committed = bool(
        domain_ok and case.get("base_permit", False) and gateway and (reuse or renewed)
    )
    return dict(
        reuse=reuse,
        renewed=renewed,
        prompted=not reuse,
        committed=committed,
        trace=trace if committed else [],
        binding_violation=bool(reuse and not bound),
        guard_cells=len(package["cells"]) if package else 0,
        certificate_bytes=len(sem.encode(package).encode()) if package else 0,
        compilation_ms=package["compilation_ms"] if compiled_here else 0.0,
        runtime_ms=(time.perf_counter() - start) * 1000,
        solver_status=answer["status"] if answer else None,
        unresolved_cells=len(package["unresolved"]) if package else 0,
    )


def score(case, result):
    case = sem.canonical_case(case)
    raw, state = case["query"], case.get("query_state", case.get("state", {}))
    safe = supported(raw, case["domains"]) and reference_safe(case, raw, state)
    mapped = sem.mapped(case, raw)
    runtime_safe = (
        old_preconditions(case, raw, state)
        and mapped is not None
        and sem.refines(
            result["trace"],
            case["old"],
            case,
            sem.normalized(mapped or {}, case["old"]),
            mapped or {},
            state,
        )
    )
    eligible = (
        safe
        and case.get("base_permit", False)
        and case.get("approval_valid", True)
        and not case.get("approval_revoked", False)
        and case.get("now", 0) < case.get("approval_expires", float("inf"))
    )
    return dict(
        unsafe_reuse=int(result["committed"] and not runtime_safe)
        if result["reuse"]
        else None,
        safe_recall=int(result["reuse"]) if eligible else None,
        prompt_rate=int(result["prompted"]),
        reconsent_precision=int(not safe) if result["prompted"] else None,
        compilation_ms=result["compilation_ms"],
        runtime_ms=result["runtime_ms"],
        completion=int(result["committed"]),
        binding_violation=int(result["binding_violation"]),
        guard_cells=result["guard_cells"],
        certificate_bytes=result["certificate_bytes"],
        unresolved_cells=result["unresolved_cells"],
        legal_effects=len(result["trace"]) if runtime_safe or result["renewed"] else 0,
    )


def metric_counts(case, result):
    return {
        key: [value, 1] if value is not None else [0, 0]
        for key, value in score(case, result).items()
        if key
        in (
            "unsafe_reuse",
            "safe_recall",
            "prompt_rate",
            "reconsent_precision",
            "completion",
            "binding_violation",
        )
    }
