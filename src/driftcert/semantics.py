"""Typed dual-version interpretation, canonical identities and prefix languages."""

import copy
import json

MISSING = "__MISSING__"


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def equal(left, right):
    return encode(left) == encode(right)


def subset(left, right):
    return (
        isinstance(left, list)
        and isinstance(right, list)
        and all(any(equal(item, other) for other in right) for item in left)
    )


def compare(left, operation, right):
    if operation == "eq":
        return equal(left, right)
    if operation == "ne":
        return not equal(left, right)
    if operation == "subset":
        return subset(left, right)
    if operation == "contains":
        return isinstance(left, list) and any(equal(item, right) for item in left)
    if type(left) not in (int, float) or type(right) not in (int, float):
        return False
    return {
        "lt": left < right,
        "le": left <= right,
        "gt": left > right,
        "ge": left >= right,
    }[operation]


def canonical_recipient(value, aliases):
    seen = set()
    while value in aliases:
        if value in seen:
            raise ValueError("Recipient alias cycle")
        seen.add(value)
        value = aliases[value]
    return value


def label_leq(actual, maximum, edges):
    seen = {actual}
    while True:
        following = seen | {right for left, right in edges if left in seen}
        if maximum in following:
            return True
        if following == seen:
            return False
        seen = following


def normalized(raw, contract):
    return {**copy.deepcopy(contract.get("defaults", {})), **copy.deepcopy(raw)}


def old_parameters(case):
    old = case["old"]
    requires = old.get("requires", {})
    direct = (
        set(requires)
        if isinstance(requires, dict)
        and not set(requires) & {"all", "any", "not", "compare", "present"}
        else set()
    )

    def references(item):
        if isinstance(item, str):
            return (
                {item[1:]}
                if item.startswith("$") and not item.startswith(("$state.", "$raw."))
                else set()
            )
        if isinstance(item, list):
            return (
                set().union(*(references(value) for value in item)) if item else set()
            )
        if isinstance(item, dict):
            if "literal" in item:
                return set()
            return (
                set().union(*(references(value) for value in item.values()))
                if item
                else set()
            ) | (
                {item["present"]}
                if "present" in item and not item["present"].startswith("state.")
                else set()
            )
        return set()

    return (
        set(old.get("parameters", []))
        | set(old.get("defaults", {}))
        | direct
        | set(old.get("required_parameters", []))
        | references(old)
    )


def mapped(case, raw):
    parameters = old_parameters(case)
    result = {}
    for name, value in raw.items():
        destination = case.get("mapping", {}).get(
            name, name if name in parameters else None
        )
        if destination == "__DROP__":
            continue
        if (
            destination is None
            or destination not in parameters
            or destination in result
        ):
            return None
        result[destination] = copy.deepcopy(value)
    return result


def lookup(name, args, state, raw):
    if name.startswith("state."):
        return state[name[6:]]
    if name.startswith("raw."):
        return raw[name[4:]]
    return args[name]


def value(expression, args, state=None, raw=None):
    state, raw = state or {}, raw or {}
    if isinstance(expression, str) and expression.startswith("$"):
        return copy.deepcopy(lookup(expression[1:], args, state, raw))
    if isinstance(expression, list):
        return [value(item, args, state, raw) for item in expression]
    if isinstance(expression, dict):
        if "literal" in expression:
            return copy.deepcopy(expression["literal"])
        if "if" in expression:
            return value(
                expression["then"]
                if condition(expression["if"], args, state, raw)
                else expression["else"],
                args,
                state,
                raw,
            )
        for operation in ("union", "intersection", "difference"):
            if operation in expression:
                groups = [
                    value(item, args, state, raw) for item in expression[operation]
                ]
                if not all(isinstance(group, list) for group in groups):
                    raise ValueError("Set expression requires lists")
                keys = [{encode(item): item for item in group} for group in groups]
                selected = set(keys[0]) if keys else set()
                for other in keys[1:]:
                    selected = (
                        selected | set(other)
                        if operation == "union"
                        else selected & set(other)
                        if operation == "intersection"
                        else selected - set(other)
                    )
                values = {key: item for group in keys for key, item in group.items()}
                return [values[key] for key in sorted(selected)]
        raise ValueError("Unsupported effect expression")
    return copy.deepcopy(expression)


def condition(expression, args, state=None, raw=None):
    state, raw = state or {}, raw or {}
    if isinstance(expression, bool):
        return expression
    if "all" in expression:
        return all(condition(item, args, state, raw) for item in expression["all"])
    if "any" in expression:
        return any(condition(item, args, state, raw) for item in expression["any"])
    if "not" in expression:
        return not condition(expression["not"], args, state, raw)
    if "present" in expression:
        name = expression["present"]
        return name[6:] in state if name.startswith("state.") else name in raw
    if "compare" in expression:
        left, operation, right = expression["compare"]
        try:
            return compare(
                value(left, args, state, raw), operation, value(right, args, state, raw)
            )
        except KeyError:
            return False
    try:
        return all(
            equal(lookup(name, args, state, raw), expected)
            for name, expected in expression.items()
        )
    except KeyError:
        return False


def traces(raw, contract, state=None):
    args = normalized(raw, contract)
    result = []
    for branch in contract.get("traces", [contract.get("effects", [])]):
        events = []
        for specification in branch:
            if not condition(specification.get("when", True), args, state, raw):
                continue
            if not condition(specification.get("requires", True), args, state, raw):
                break
            events.append(
                {
                    name: value(item, args, state, raw)
                    for name, item in specification.items()
                    if name not in ("when", "requires", "optional")
                }
            )
        result.append(events)
    return result


def match(effect, rule, case, args=None, raw=None, state=None):
    args, raw, state = args or {}, raw or {}, state or {}
    try:
        if not condition(rule.get("requires", True), args, state, raw):
            return False
        aliases = case.get("recipient_aliases", {})
        objects = value(rule["objects"], args, state, raw)
        recipients = value(rule["recipients"], args, state, raw)
        labels = value(rule["labels"], args, state, raw)
        return (
            equal(effect["action"], value(rule["action"], args, state, raw))
            and subset(effect["objects"], objects)
            and any(
                canonical_recipient(effect["recipient"], aliases)
                == canonical_recipient(item, aliases)
                for item in recipients
            )
            and any(
                label_leq(effect["label"], item, case.get("label_order", []))
                for item in labels
            )
        )
    except KeyError:
        return False


def refines(trace, contract, case=None, args=None, raw=None, state=None):
    case, args, raw, state = case or {}, args or {}, raw or {}, state or {}
    for allowed in contract.get("traces", [contract.get("allowed", [])]):
        positions = {0}
        for effect in trace:
            following = set()
            for start in positions:
                for index in range(start, len(allowed)):
                    rule = allowed[index]
                    active = condition(rule.get("when", True), args, state, raw)
                    if active and match(effect, rule, case, args, raw, state):
                        following.add(index + 1)
                    if active and not rule.get("optional", False):
                        break
            positions = following
            if not positions:
                break
        if positions:
            return True
    return False


def safe(case, raw, state=None):
    case = canonical_case(case)
    raw = canonical_raw(case, raw)
    previous = mapped(case, raw)
    if previous is None:
        return False
    args = normalized(previous, case["old"])
    if not integers_in_range(args, case.get("integer_bits", 64)):
        return False
    if not condition(case["old"].get("requires", True), args, state, previous):
        return False
    if any(name not in args for name in case["old"].get("required_parameters", [])):
        return False
    return all(
        refines(trace, case["old"], case, args, previous, state)
        for trace in traces(raw, case["new"], state)
    )


def valid_new(case, raw, state=None):
    """Check the declared typed new-call fragment before attempting reuse."""
    bits = case.get("integer_bits", 64)
    if not integers_in_range([raw, state or {}, case["new"].get("defaults", {})], bits):
        return False
    args = normalized(raw, case["new"])
    if not condition(case["new"].get("requires", True), args, state, raw):
        return False
    try:
        branches = traces(raw, case["new"], state)
    except KeyError:
        return False
    return all(
        all(type(event.get(name)) is str for name in ("action", "recipient", "label"))
        and isinstance(event.get("objects"), list)
        and all(type(item) is str for item in event["objects"])
        for branch in branches
        for event in branch
    )


def failure(case, raw, state=None):
    """Explain a concrete refinement witness in its violated effect dimension."""

    def references(item):
        if isinstance(item, str) and item.startswith("$"):
            return {"@state." + item[7:] if item.startswith("$state.") else item[1:]}
        if isinstance(item, list):
            return (
                set().union(*(references(child) for child in item)) if item else set()
            )
        if isinstance(item, dict):
            result = (
                set().union(*(references(child) for child in item.values()))
                if item
                else set()
            )
            if "present" in item:
                result.add(item["present"])
            if not set(item) & {"all", "any", "not", "compare", "present"}:
                result.update(item)
            return result
        return set()

    old = mapped(case, raw)
    if old is None:
        return dict(reason="mapping", fields=sorted(raw), guards=[])
    previous = normalized(old, case["old"])
    if not condition(case["old"].get("requires", True), previous, state, old):
        return dict(
            reason="old_precondition",
            fields=sorted(references(case["old"].get("requires", {}))),
            guards=[],
        )
    current = normalized(raw, case["new"])
    aliases = case.get("recipient_aliases", {})
    rules = [
        rule
        for branch in case["old"].get("traces", [case["old"].get("allowed", [])])
        for rule in branch
        if condition(rule.get("when", True), previous, state, old)
    ]
    for branch in case["new"].get("traces", [case["new"].get("effects", [])]):
        prefix = []
        for spec in branch:
            if not condition(spec.get("when", True), current, state, raw):
                continue
            if not condition(spec.get("requires", True), current, state, raw):
                break
            event = {
                name: value(item, current, state, raw)
                for name, item in spec.items()
                if name not in ("when", "requires", "optional")
            }
            prefix.append(event)
            if refines(prefix, case["old"], case, previous, old, state):
                continue
            candidates = [
                rule
                for rule in rules
                if equal(value(rule["action"], previous, state, old), event["action"])
            ]
            dimension = "action"
            if candidates:
                scope = [
                    rule
                    for rule in candidates
                    if subset(
                        event["objects"], value(rule["objects"], previous, state, old)
                    )
                ]
                dimension = "objects"
                if scope:
                    sinks = [
                        rule
                        for rule in scope
                        if any(
                            canonical_recipient(event["recipient"], aliases)
                            == canonical_recipient(item, aliases)
                            for item in value(rule["recipients"], previous, state, old)
                        )
                    ]
                    dimension = "recipient"
                    if sinks:
                        dimension = (
                            "label"
                            if not any(
                                any(
                                    label_leq(
                                        event["label"],
                                        item,
                                        case.get("label_order", []),
                                    )
                                    for item in value(
                                        rule["labels"], previous, state, old
                                    )
                                )
                                for rule in sinks
                            )
                            else "ordering_or_precondition"
                        )
            fields = references(spec.get(dimension)) if dimension in spec else set()
            guards = references(spec.get("when", {})) | references(
                spec.get("requires", {})
            )
            if dimension == "ordering_or_precondition":
                guards |= references(branch)
            return dict(
                reason=dimension,
                effect=event,
                fields=sorted(fields),
                guards=sorted(guards),
            )
    return dict(reason="unresolved_interpretation", fields=[], guards=[])


def integers_in_range(item, bits):
    if type(item) is int:
        return -(2 ** (bits - 1)) <= item < 2 ** (bits - 1)
    if isinstance(item, list):
        return all(integers_in_range(value, bits) for value in item)
    if isinstance(item, dict):
        return all(integers_in_range(value, bits) for value in item.values())
    return True


def canonical_set(items):
    if not isinstance(items, list):
        return items
    unique = {encode(item): copy.deepcopy(item) for item in items}
    return [unique[key] for key in sorted(unique)]


def canonical_raw(case, raw):
    return {
        name: canonical_set(item)
        if name in case.get("set_fields", [])
        else copy.deepcopy(item)
        for name, item in raw.items()
    }


def canonical_case(case):
    """Canonicalize declared set inputs without changing general JSON arrays."""
    result = copy.deepcopy(case)
    fields = set(case.get("set_fields", []))

    def find(item):
        if isinstance(item, dict):
            expression = item.get("objects")
            if (
                isinstance(expression, str)
                and expression.startswith("$")
                and not expression.startswith(("$state.", "$raw."))
            ):
                fields.add(expression[1:])
            for child in item.values():
                find(child)
        elif isinstance(item, list):
            for child in item:
                find(child)

    find(case.get("new", {}))
    result["set_fields"] = sorted(fields)
    for name in fields:
        if name in result.get("domains", {}):
            values = [canonical_set(item) for item in result["domains"][name]]
            result["domains"][name] = list(
                {encode(value): value for value in values}.values()
            )
    old_fields = {result.get("mapping", {}).get(name, name) for name in fields}

    def rewrite(item, names):
        if isinstance(item, dict):
            for key, value in item.items():
                if key in names and isinstance(value, list):
                    item[key] = canonical_set(value)
                elif key == "compare" and isinstance(value, list) and len(value) == 3:
                    for left, right in ((0, 2), (2, 0)):
                        if (
                            isinstance(value[left], str)
                            and value[left].startswith("$")
                            and value[left][1:] in names
                            and isinstance(value[right], list)
                        ):
                            value[right] = canonical_set(value[right])
                else:
                    rewrite(value, names)
        elif isinstance(item, list):
            for child in item:
                rewrite(child, names)

    rewrite(result.get("old", {}), old_fields)
    rewrite(result.get("new", {}), fields)
    if "query" in result:
        result["query"] = canonical_raw(result, result["query"])
    return result
