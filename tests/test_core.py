import random
import unittest

from driftcert import core


class DriftCertTests(unittest.TestCase):
    def test_effect_guards_preserve_boolean_integer_and_missing_null(self):
        effect = dict(action="export", objects=["private"], recipient="remote",
                      label="private", when={"flag": 1})
        self.assertEqual(core.effects({"flag": True}, {"effects": [effect]}), [])
        effect["when"] = {"flag": None}
        self.assertEqual(core.effects({}, {"effects": [effect]}), [])
        self.assertEqual(len(core.effects({"flag": None}, {"effects": [effect]})), 1)

    def test_gateway_does_not_equate_boolean_and_integer_effect_fields(self):
        case = self.case()
        case["runtime_trace"] = core.effects(case["query"], case["new"])
        case["new"]["effects"][0]["audit_version"] = 1
        case["runtime_trace"][0]["audit_version"] = True
        self.assertFalse(core.run_case(case, "driftcert")["committed"])

    def case(self):
        case = next(core.generate(random.Random(17), 1))
        case.update(
            query={"remote": False, "recipient": "local", "objects": ["public"]},
            bound_version=1,
            current_version=1,
            base_permit=True,
        )
        return case

    def test_per_call_must_preserve_old_preconditions(self):
        case = self.case()
        case["old"]["requires"] = {"approved": True}
        self.assertFalse(core.run_case(case, "per_call")["committed"])

    def test_unsafe_reuse_denominator_includes_old_consent_calls_without_commit(self):
        case = self.case()
        case["base_permit"] = False
        result = core.run_case(case, "driftcert")
        self.assertTrue(result["reuse"])
        self.assertEqual(core.score(case, result)["unsafe_reuse"], 0)

    def test_unsupported_input_cannot_use_global_guard(self):
        case = self.case()
        case["new"]["defaults"]["remote"] = False
        case["domains"]["remote"] = [False]
        case["domains"]["recipient"] = ["local"]
        case["domains"]["objects"] = [["public"]]
        case["query"]["unreviewed"] = True
        self.assertFalse(core.run_case(case, "global")["reuse"])

    def test_unexpected_gateway_effect_never_commits(self):
        case = self.case()
        case["runtime_trace"] = [
            dict(
                action="export",
                objects=["private"],
                recipient="remote",
                label="private",
            )
        ]
        self.assertFalse(core.run_case(case, "driftcert")["committed"])


if __name__ == "__main__":
    unittest.main()
