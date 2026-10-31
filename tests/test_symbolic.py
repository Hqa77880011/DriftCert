import random
import unittest

from driftcert import compiler, core, oracle, semantics
from driftcert.symbolic import Model


class SymbolicTests(unittest.TestCase):
    def test_safe_cell_union_bdd_and_serialized_guard_match_exact_oracle(self):
        import json

        case = next(core.generate(random.Random(17), 1))
        for method in ("driftcert", "uniform", "global"):
            package = compiler.compile_guard(case, method)
            restored = json.loads(json.dumps(package, allow_nan=False))
            for raw in core.universe(case["domains"]):
                wanted = oracle.safe(case, raw) if method != "global" else False
                self.assertEqual(
                    compiler.accepts(package, raw, representation="dnf"), wanted
                )
                self.assertEqual(compiler.accepts(package, raw), wanted)
                self.assertEqual(compiler.accepts(restored, raw), wanted)

    def test_seeded_defect_is_rejected_by_independent_checker(self):
        case = next(core.generate(random.Random(17), 1))
        case["guard_fault"] = True
        raw = {"recipient": "local", "objects": ["public"]}
        checked = compiler.compile_guard(case)
        unchecked = compiler.compile_guard(case, "no_checker")
        self.assertFalse(compiler.accepts(checked, raw))
        self.assertTrue(compiler.accepts(unchecked, raw))
        self.assertFalse(oracle.safe(case, raw))

    def test_two_symbolic_encoders_match_independent_finite_oracle(self):
        case = next(core.generate(random.Random(17), 1))
        model = Model(case)
        for raw in core.universe(case["domains"]):
            raw = semantics.canonical_raw(model.case, raw)
            point = {
                name: [
                    next(
                        index
                        for index, value in enumerate(values)
                        if semantics.equal(value, raw.get(name, semantics.MISSING))
                    )
                ]
                for name, values in model.domains.items()
            }
            expected = not oracle.safe(case, raw)
            self.assertEqual(semantics.safe(case, raw), not expected)
            for independent in (False, True):
                answer = model.query(point, independent, 2000)
                self.assertEqual(answer["status"], "SAT" if expected else "UNSAT")

    def test_state_alias_label_and_multiple_trace_quantification(self):
        case = dict(
            domains={"mfa": [False, True, semantics.MISSING]},
            state_domains={"level": [0, 1]},
            state={"level": 1},
            old=dict(
                parameters=["mfa"],
                defaults={"mfa": False},
                requires={},
                allowed=[
                    dict(
                        action="export",
                        objects=["p"],
                        recipients=["local"],
                        labels=["internal"],
                    )
                ],
            ),
            new=dict(
                defaults={"mfa": True},
                traces=[
                    [
                        dict(
                            action="export",
                            objects=["p"],
                            recipient="alias",
                            label="public",
                            when={"compare": ["$state.level", "ge", 1]},
                        )
                    ],
                    [
                        dict(
                            action="export",
                            objects=["p"],
                            recipient="remote",
                            label="public",
                            when={"mfa": False},
                        )
                    ],
                ],
            ),
            mapping={},
            recipient_aliases={"alias": "local"},
            label_order=[["public", "internal"]],
        )
        model = Model(case)
        for mfa in (False, True, semantics.MISSING):
            for level in (0, 1):
                raw = {} if mfa == semantics.MISSING else {"mfa": mfa}
                point = {
                    "mfa": [case["domains"]["mfa"].index(mfa)],
                    "@state.level": [level],
                }
                expected = semantics.safe(case, raw, {"level": level})
                for independent in (False, True):
                    self.assertEqual(
                        model.query(point, independent, 2000)["status"],
                        "UNSAT" if expected else "SAT",
                    )

    def test_presence_null_and_boolean_integer_are_distinct(self):
        case = next(core.generate(random.Random(17), 1))
        case["domains"]["remote"] = [False, True, None, 0, 1, semantics.MISSING]
        model = Model(case)
        self.assertEqual(len(model.domains["remote"]), 6)
        for raw in core.universe(case["domains"]):
            raw = semantics.canonical_raw(model.case, raw)
            expected = semantics.safe(case, raw)
            point = {
                name: [
                    next(
                        i
                        for i, value in enumerate(values)
                        if semantics.equal(value, raw.get(name, semantics.MISSING))
                    )
                ]
                for name, values in model.domains.items()
            }
            self.assertEqual(
                model.query(point)["status"], "UNSAT" if expected else "SAT"
            )

    def test_set_canonicalization_and_signed_integer_boundaries(self):
        case = next(core.generate(random.Random(17), 1))
        case["domains"]["objects"] = [
            ["private", "public"],
            ["public", "private"],
            ["public"],
        ]
        package = compiler.compile_guard(case)
        self.assertEqual(len(package["domains"]["objects"]), 2)
        raw = dict(remote=False, recipient="local", objects=["public", "public"])
        self.assertTrue(compiler.accepts(package, raw))
        case["domains"]["number"] = [-(2**63), 2**63 - 1, 2**63]
        case["mapping"]["number"] = "__DROP__"
        self.assertFalse(semantics.valid_new(case, {**raw, "number": 2**63}))
        self.assertTrue(semantics.valid_new(case, {**raw, "number": 2**63 - 1}))
