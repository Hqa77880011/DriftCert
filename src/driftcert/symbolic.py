"""Finite symbolic effect refinement with independent automaton encodings."""

import copy
import itertools

import z3

from . import semantics as sem


class Model:
    """Keep raw presence and both normalizers symbolic over declared finite types."""

    def __init__(self, case):
        case = sem.canonical_case(case)
        self.case = copy.deepcopy(case)
        self.domains = {
            **case["domains"],
            **{
                "@state." + key: values
                for key, values in case.get("state_domains", {}).items()
            },
        }
        if any(name.startswith("@state.") for name in case["domains"]):
            raise ValueError("Reserved state-variable prefix")
        self.variables = {
            name: z3.Int("input_" + str(index))
            for index, name in enumerate(sorted(self.domains))
        }
        self.bounds = z3.And(
            *(
                z3.And(variable >= 0, variable < len(self.domains[name]))
                for name, variable in self.variables.items()
            )
        )
        self.raw = {
            name: [
                (value, variable == index)
                for index, value in enumerate(self.domains[name])
                if not sem.equal(value, sem.MISSING)
            ]
            for name, variable in self.variables.items()
            if not name.startswith("@state.")
        }
        self.state = {
            name: list(self.constant(value))
            for name, value in case.get("state", {}).items()
        }
        for name, variable in self.variables.items():
            if name.startswith("@state."):
                self.state[name[7:]] = [
                    (value, variable == index)
                    for index, value in enumerate(self.domains[name])
                    if not sem.equal(value, sem.MISSING)
                ]
        self.new = self.normalized(case["new"], self.raw)
        old_raw = {name: [] for name in sem.old_parameters(case)}
        defined = []
        origins = {}
        for name, choices in self.raw.items():
            destination = case.get("mapping", {}).get(
                name, name if name in old_raw else None
            )
            present = z3.Or(*(condition for _, condition in choices))
            if destination == "__DROP__":
                continue
            if destination not in old_raw:
                defined.append(z3.Not(present))
                continue
            for other in origins.get(destination, []):
                defined.append(z3.Not(z3.And(other, present)))
            origins.setdefault(destination, []).append(present)
            old_raw[destination] += choices
        self.old_raw = old_raw
        self.old = self.normalized(case["old"], old_raw)
        self.mapping_defined = z3.And(
            *defined,
            *(
                z3.Or(*(condition for _, condition in self.old.get(name, [])))
                for name in case["old"].get("required_parameters", [])
            ),
        )
        self.old_pre = self.condition(
            case["old"].get("requires", True), self.old, self.old_raw
        )
        self.domain = z3.And(
            self.bounds,
            self.condition(case["new"].get("requires", True), self.new, self.raw),
        )
        bits = case.get("integer_bits", 64)
        valid = []
        for name, values in self.domains.items():
            for index, value in enumerate(values):
                if not sem.integers_in_range(value, bits):
                    valid.append(self.variables[name] != index)
        for choices in self.new.values():
            valid.extend(
                z3.Not(condition)
                for value, condition in choices
                if not sem.integers_in_range(value, bits)
            )
        self.mapping_defined = z3.And(
            self.mapping_defined,
            *(
                z3.Not(condition)
                for choices in self.old.values()
                for value, condition in choices
                if not sem.integers_in_range(value, bits)
            ),
        )
        self.domain = z3.And(self.domain, *valid)
        self.bad = self.forward_bad()
        self.independent_bad = self.matching_bad()

    @staticmethod
    def constant(value):
        return [(copy.deepcopy(value), z3.BoolVal(True))]

    def normalized(self, contract, raw):
        result = {name: list(values) for name, values in raw.items()}
        for name, value in contract.get("defaults", {}).items():
            choices = result.setdefault(name, [])
            choices.append(
                (
                    copy.deepcopy(value),
                    z3.Not(z3.Or(*(condition for _, condition in choices))),
                )
            )
        return result

    def presence(self, name, raw):
        choices = (
            self.state.get(name[6:], [])
            if name.startswith("state.")
            else raw.get(name, [])
        )
        return z3.Or(*(condition for _, condition in choices))

    def choices(self, expression, environment, raw):
        if isinstance(expression, str) and expression.startswith("$"):
            name = expression[1:]
            return (
                self.state.get(name[6:], [])
                if name.startswith("state.")
                else raw.get(name[4:], [])
                if name.startswith("raw.")
                else environment.get(name, [])
            )
        if isinstance(expression, list):
            groups = [self.choices(item, environment, raw) for item in expression]
            return [
                (
                    [item[0] for item in combination],
                    z3.And(*(item[1] for item in combination)),
                )
                for combination in itertools.product(*groups)
            ]
        if isinstance(expression, dict):
            if "literal" in expression:
                return self.constant(expression["literal"])
            if "if" in expression:
                selected = self.condition(expression["if"], environment, raw)
                return [
                    (value, z3.And(selected, condition))
                    for value, condition in self.choices(
                        expression["then"], environment, raw
                    )
                ] + [
                    (value, z3.And(z3.Not(selected), condition))
                    for value, condition in self.choices(
                        expression["else"], environment, raw
                    )
                ]
            for operation in ("union", "intersection", "difference"):
                if operation in expression:
                    groups = [
                        self.choices(item, environment, raw)
                        for item in expression[operation]
                    ]
                    return [
                        (
                            sem.value(
                                {
                                    operation: [
                                        {"literal": item[0]} for item in combination
                                    ]
                                },
                                {},
                            ),
                            z3.And(*(item[1] for item in combination)),
                        )
                        for combination in itertools.product(*groups)
                    ]
            raise ValueError("Unsupported symbolic effect expression")
        return self.constant(expression)

    def relation(self, left, operation, right):
        return z3.Or(
            *(
                z3.And(a_condition, b_condition)
                for a, a_condition in left
                for b, b_condition in right
                if sem.compare(a, operation, b)
            )
        )

    def condition(self, expression, environment, raw):
        if isinstance(expression, bool):
            return z3.BoolVal(expression)
        if "all" in expression:
            return z3.And(
                *(self.condition(item, environment, raw) for item in expression["all"])
            )
        if "any" in expression:
            return z3.Or(
                *(self.condition(item, environment, raw) for item in expression["any"])
            )
        if "not" in expression:
            return z3.Not(self.condition(expression["not"], environment, raw))
        if "present" in expression:
            return self.presence(expression["present"], raw)
        if "compare" in expression:
            left, operation, right = expression["compare"]
            return self.relation(
                self.choices(left, environment, raw),
                operation,
                self.choices(right, environment, raw),
            )
        return z3.And(
            *(
                self.relation(
                    self.choices("$" + name, environment, raw),
                    "eq",
                    self.constant(expected),
                )
                for name, expected in expression.items()
            )
        )

    def fields(self, specification, environment, raw):
        return {
            name: self.choices(value, environment, raw)
            for name, value in specification.items()
            if name not in ("when", "requires", "optional")
        }

    def branches(self):
        for branch in self.case["new"].get(
            "traces", [self.case["new"].get("effects", [])]
        ):
            live = z3.BoolVal(True)
            events = []
            for specification in branch:
                when = self.condition(
                    specification.get("when", True), self.new, self.raw
                )
                pre = self.condition(
                    specification.get("requires", True), self.new, self.raw
                )
                active = z3.And(live, when, pre)
                fields = self.fields(specification, self.new, self.raw)

                def typed(name, value):
                    return (
                        isinstance(value, list)
                        and all(type(item) is str for item in value)
                        if name == "objects"
                        else type(value) is str
                        if name in ("action", "recipient", "label")
                        else True
                    )

                self.domain = z3.And(
                    self.domain,
                    z3.Implies(
                        active,
                        z3.And(
                            *(
                                z3.Or(
                                    *(
                                        condition
                                        for value, condition in choices
                                        if typed(name, value)
                                    )
                                )
                                for name, choices in fields.items()
                            )
                        ),
                    ),
                )
                events.append((active, fields))
                live = z3.And(live, z3.Or(z3.Not(when), pre))
            yield events

    def old_rules(self, allowed):
        return [
            (
                self.condition(rule.get("when", True), self.old, self.old_raw),
                self.condition(rule.get("requires", True), self.old, self.old_raw),
                bool(rule.get("optional", False)),
                self.fields(rule, self.old, self.old_raw),
            )
            for rule in allowed
        ]

    def matches(self, effect, rule):
        aliases = self.case.get("recipient_aliases", {})
        recipient = z3.Or(
            *(
                z3.And(left_condition, right_condition)
                for left, left_condition in effect["recipient"]
                for values, right_condition in rule["recipients"]
                if any(
                    sem.canonical_recipient(left, aliases)
                    == sem.canonical_recipient(right, aliases)
                    for right in values
                )
            )
        )
        label = z3.Or(
            *(
                z3.And(left_condition, right_condition)
                for left, left_condition in effect["label"]
                for values, right_condition in rule["labels"]
                if any(
                    sem.label_leq(left, right, self.case.get("label_order", []))
                    for right in values
                )
            )
        )
        return z3.And(
            self.relation(effect["action"], "eq", rule["action"]),
            self.relation(effect["objects"], "subset", rule["objects"]),
            recipient,
            label,
        )

    def forward_bad(self):
        failures = []
        old_languages = self.case["old"].get(
            "traces", [self.case["old"].get("allowed", [])]
        )
        for branch in self.branches():
            accepting = []
            for allowed in old_languages:
                rules = self.old_rules(allowed)
                positions = [z3.BoolVal(index == 0) for index in range(len(rules) + 1)]
                for active, effect in branch:
                    following = [z3.And(z3.Not(active), item) for item in positions]
                    for start, reachable in enumerate(positions):
                        skips = z3.BoolVal(True)
                        for index in range(start, len(rules)):
                            enabled, pre, optional, fields = rules[index]
                            following[index + 1] = z3.Or(
                                following[index + 1],
                                z3.And(
                                    active,
                                    reachable,
                                    skips,
                                    enabled,
                                    pre,
                                    self.matches(effect, fields),
                                ),
                            )
                            skips = z3.And(skips, z3.Or(z3.Not(enabled), optional))
                    positions = following
                accepting.append(z3.Or(*positions))
            failures.append(z3.Not(z3.Or(*accepting)))
        return z3.Or(z3.Not(self.mapping_defined), z3.Not(self.old_pre), *failures)

    def matching_bad(self):
        """Independent existential transition matching, not cached forward reachability."""
        failures = []
        for branch_index, branch in enumerate(self.branches()):
            languages = []
            for language_index, allowed in enumerate(
                self.case["old"].get("traces", [self.case["old"].get("allowed", [])])
            ):
                rules = self.old_rules(allowed)
                variables = []
                constraints = []
                previous = z3.IntVal(-1)
                for event_index, (active, effect) in enumerate(branch):
                    position = z3.Int(
                        f"checker_{branch_index}_{language_index}_{event_index}"
                    )
                    variables.append(position)
                    compatible = z3.Or(
                        *(
                            z3.And(
                                position == index,
                                enabled,
                                pre,
                                self.matches(effect, fields),
                            )
                            for index, (enabled, pre, _, fields) in enumerate(rules)
                        )
                    )
                    preserved = z3.And(
                        *(
                            z3.Implies(
                                z3.And(previous < index, index < position),
                                z3.Or(z3.Not(enabled), optional),
                            )
                            for index, (enabled, _, optional, _) in enumerate(rules)
                        )
                    )
                    constraints.append(
                        z3.Implies(
                            active,
                            z3.And(
                                previous < position,
                                position >= 0,
                                position < len(rules),
                                compatible,
                                preserved,
                            ),
                        )
                    )
                    previous = z3.If(active, position, previous)
                formula = z3.And(*constraints)
                languages.append(
                    z3.Exists(variables, formula) if variables else formula
                )
            failures.append(z3.Not(z3.Or(*languages)))
        return z3.Or(z3.Not(self.mapping_defined), z3.Not(self.old_pre), *failures)

    def cell_formula(self, cell):
        return z3.And(
            *(
                z3.Or(*(self.variables[name] == index for index in indices))
                for name, indices in cell.items()
            )
        )

    def point(self, model):
        raw, state = {}, copy.deepcopy(self.case.get("state", {}))
        indices = {}
        for name, variable in self.variables.items():
            index = model.eval(variable, model_completion=True).as_long()
            indices[name] = index
            value = self.domains[name][index]
            if name.startswith("@state."):
                if not sem.equal(value, sem.MISSING):
                    state[name[7:]] = copy.deepcopy(value)
                else:
                    state.pop(name[7:], None)
            elif not sem.equal(value, sem.MISSING):
                raw[name] = copy.deepcopy(value)
        return raw, state, indices

    def query(self, cell, independent=False, timeout_ms=1000):
        solver = z3.Solver()
        solver.set(timeout=max(1, int(timeout_ms)))
        solver.add(
            self.domain,
            self.cell_formula(cell),
            self.independent_bad if independent else self.bad,
        )
        verdict = solver.check()
        if verdict == z3.sat:
            raw, state, indices = self.point(solver.model())
            return dict(status="SAT", raw=raw, state=state, indices=indices)
        return dict(
            status="UNSAT" if verdict == z3.unsat else "UNKNOWN",
            reason=solver.reason_unknown(),
        )
