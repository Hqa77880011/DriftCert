"""Independent recursive finite trace oracle.

Primitive typed expressions are trusted IR parsing. This interpreter rebuilds
mapping, dual normalization, effects and recursive transition matching; it does
not consult compiler cells, symbolic formulas or cached synthesis decisions.
"""

import copy
from functools import lru_cache

from . import semantics as sem


def safe(case, raw, state=None):
    try:
        return interpret(case, raw, state)
    except KeyError:
        return False


def interpret(case, raw, state=None):
    case = sem.canonical_case(case)
    raw = sem.canonical_raw(case, raw)
    state = state or {}
    names = sem.old_parameters(case)
    previous = {}
    for name, item in raw.items():
        target = case.get("mapping", {}).get(name, name if name in names else None)
        if target == "__DROP__":
            continue
        if target not in names or target in previous:
            return False
        previous[target] = copy.deepcopy(item)
    old = {**copy.deepcopy(case["old"].get("defaults", {})), **previous}
    new = {**copy.deepcopy(case["new"].get("defaults", {})), **copy.deepcopy(raw)}
    if not sem.integers_in_range(old, case.get("integer_bits", 64)):
        return False
    if not sem.condition(case["old"].get("requires", True), old, state, previous):
        return False
    if any(name not in old for name in case["old"].get("required_parameters", [])):
        return False
    for branch in case["new"].get("traces", [case["new"].get("effects", [])]):
        events = []
        for spec in branch:
            if not sem.condition(spec.get("when", True), new, state, raw):
                continue
            if not sem.condition(spec.get("requires", True), new, state, raw):
                break
            events.append(
                {
                    key: sem.value(item, new, state, raw)
                    for key, item in spec.items()
                    if key not in ("when", "requires", "optional")
                }
            )
        accepted = False
        for rules in case["old"].get("traces", [case["old"].get("allowed", [])]):

            @lru_cache(None)
            def visit(event, rule):
                if event == len(events):
                    return True
                if rule == len(rules):
                    return False
                item = rules[rule]
                active = sem.condition(item.get("when", True), old, state, previous)
                if not active:
                    return visit(event, rule + 1)
                actual = events[event]
                aliases = case.get("recipient_aliases", {})
                matches = (
                    sem.condition(item.get("requires", True), old, state, previous)
                    and sem.equal(
                        actual["action"],
                        sem.value(item["action"], old, state, previous),
                    )
                    and sem.subset(
                        actual["objects"],
                        sem.value(item["objects"], old, state, previous),
                    )
                    and any(
                        sem.canonical_recipient(actual["recipient"], aliases)
                        == sem.canonical_recipient(value, aliases)
                        for value in sem.value(item["recipients"], old, state, previous)
                    )
                    and any(
                        sem.label_leq(
                            actual["label"], value, case.get("label_order", [])
                        )
                        for value in sem.value(item["labels"], old, state, previous)
                    )
                )
                return bool(
                    matches
                    and visit(event + 1, rule + 1)
                    or item.get("optional", False)
                    and visit(event, rule + 1)
                )

            if visit(0, 0):
                accepted = True
                break
        if not accepted:
            return False
    return True
