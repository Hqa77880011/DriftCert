import copy
import itertools
import json


METHODS = [
    "driftcert",
    "pin",
    "schema",
    "global",
    "per_call",
    "no_default_expansion",
    "no_version_binding",
    "no_gateway",
]


def normalized(raw, contract):
    result = copy.deepcopy(contract.get("defaults", {}))
    result.update(raw)
    return result


def effects(raw, contract):
    args = normalized(raw, contract)
    trace = []
    for effect in contract["effects"]:
        if all(args.get(k) == v for k, v in effect.get("when", {}).items()):
            value = {k: copy.deepcopy(v) for k, v in effect.items() if k != "when"}
            for key, item in list(value.items()):
                if isinstance(item, str) and item.startswith("$"):
                    if item[1:] not in args:
                        raise ValueError("Unresolved effect argument")
                    value[key] = copy.deepcopy(args[item[1:]])
            trace.append(value)
    return trace


def refines(trace, contract):
    states = {0}
    allowed = contract["allowed"]
    for effect in trace:
        following = set()
        for start in states:
            for position in range(start, len(allowed)):
                if any(not allowed[j].get("optional", False) for j in range(start, position)):
                    break
                rule = allowed[position]
                if (
                    effect["action"] == rule["action"]
                    and set(effect["objects"]) <= set(rule["objects"])
                    and effect["recipient"] in rule["recipients"]
                    and effect["label"] in rule["labels"]
                ):
                    following.add(position + 1)
        states = following
        if not states:
            return False
    return True


def universe(domains):
    keys = sorted(domains)
    for values in itertools.product(*(domains[k] for k in keys)):
        yield {k: v for k, v in zip(keys, values) if v != "__MISSING__"}


def compile_guard(case, method):
    safe = []
    old = case["old"]
    for raw in universe(case["domains"]):
        mapped = {case["mapping"].get(k, k): v for k, v in raw.items()}
        current = case["new"]
        if method == "no_default_expansion":
            current = {**current, "defaults": old.get("defaults", {})}
        trace = effects(raw, current)
        compatible = all(
            normalized(mapped, old).get(k) == v for k, v in old.get("requires", {}).items()
        )
        if compatible and refines(trace, old):
            safe.append(raw)
    return safe


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
                {"action": "audit", "objects": "$objects", "recipient": "local", "label": "public"},
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
        query = rng.choice(list(universe(domains)))
        yield {
            "id": str(index),
            "family": "default-recipient-scope",
            "old": old,
            "new": new,
            "domains": domains,
            "mapping": {},
            "query": query,
            "bound_version": 1,
            "current_version": 2 if rng.random() < 0.15 else 1,
            "base_permit": rng.random() < 0.95,
        }


def run_case(case, method):
    safe = compile_guard(case, method)
    query = case["query"]
    if method == "pin":
        reuse = False
    elif method == "schema":
        reuse = True
    elif method == "global":
        reuse = len(safe) == len(list(universe(case["domains"])))
    elif method == "per_call":
        reuse = refines(effects(query, case["new"]), case["old"])
    else:
        reuse = any(
            json.dumps(query, sort_keys=True) == json.dumps(x, sort_keys=True) for x in safe
        )
    bound = case["bound_version"] == case["current_version"] or method == "no_version_binding"
    trace = effects(query, case["new"])
    executed = case.get("runtime_trace", trace)
    gateway = method == "no_gateway" or executed == trace
    committed = reuse and bound and case["base_permit"] and gateway
    return {
        "reuse": reuse and bound,
        "committed": committed,
        "trace": executed if committed else [],
        "guard_cells": len(safe),
        "certificate_bytes": len(json.dumps(safe).encode()),
    }


def score(case, result):
    safe = refines(effects(case["query"], case["new"]), case["old"])
    runtime_safe = refines(result["trace"], case["old"])
    versioned_safe = safe and runtime_safe and case["bound_version"] == case["current_version"]
    return {
        "unsafe_reuse": int(not versioned_safe) if result["committed"] else None,
        "safe_recall": int(result["reuse"]) if versioned_safe and case["base_permit"] else None,
        "prompt_rate": int(not result["reuse"]),
        "completion": int(result["committed"]),
        "guard_cells": result["guard_cells"],
        "certificate_bytes": result["certificate_bytes"],
        "legal_effects": len(result["trace"]) if versioned_safe else 0,
    }
