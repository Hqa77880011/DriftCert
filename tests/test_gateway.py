import copy
import random
import secrets
import tempfile
import time
import unittest
from pathlib import Path

from driftcert import core
from driftcert.gateway import Gateway, digest


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "public.txt").write_bytes(b"actual protected bytes")
        self.case = next(core.generate(random.Random(17), 1))
        self.raw = dict(remote=False, recipient="local", objects=["public"])
        self.case["query"] = self.raw
        self.program = [
            {"emit": effect} for effect in core.effects(self.raw, self.case["new"])
        ]
        self.case["bindings"] = {"implementation_digest": digest(self.program)}
        self.gateway = Gateway(
            self.root,
            self.root / "ledger.sqlite",
            secrets.token_bytes(32),
            {"public": {"path": "public.txt", "label": "public"}},
            {"local": "local", "remote": "remote"},
        )
        for action in ("audit", "export"):
            self.gateway.set_acl("alice", action, "local", ["public"])
        self.package = core.compile_guard(self.case)
        self.bundle = self.gateway.install(self.package, "v2", "alice", "task")
        self.approval = self.gateway.approve(self.bundle, time.time() + 60)

    def tearDown(self):
        self.temp.cleanup()

    def execute(self, **kwargs):
        return self.gateway.execute(
            self.bundle,
            self.approval,
            "alice",
            "task",
            "v2",
            self.raw,
            self.program,
            **kwargs,
        )

    def test_actual_copy_receipts_reload_and_revoke(self):
        self.assertEqual(len(self.execute()), 2)
        self.assertEqual(
            (self.root / "local/public.bin").read_bytes(), b"actual protected bytes"
        )
        with self.gateway.connect() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM receipts").fetchone()[0], 2
            )
        self.gateway.revoke(self.approval)
        with self.assertRaises(PermissionError):
            self.execute()

    def test_tamper_identity_epoch_and_implementation(self):
        original = copy.deepcopy(self.bundle)
        self.bundle["payload"]["version"] = "v3"
        with self.assertRaises(PermissionError):
            self.execute()
        self.bundle = original
        with self.assertRaises(PermissionError):
            self.gateway.execute(
                self.bundle, self.approval, "bob", "task", "v2", self.raw, self.program
            )
        self.gateway.advance_epoch()
        with self.assertRaises(PermissionError):
            self.execute()

    def test_false_summary_and_real_renewed_contract(self):
        changed = copy.deepcopy(self.program)
        changed[-1]["emit"]["recipient"] = "remote"
        with self.assertRaises(PermissionError):
            self.gateway.execute(
                self.bundle,
                self.approval,
                "alice",
                "task",
                "v3",
                self.raw,
                changed,
                method="no_version_binding",
            )
        self.assertFalse((self.root / "remote").exists())
        with self.assertRaises(PermissionError):
            self.execute()
        self.gateway.advance_epoch()
        self.bundle = self.gateway.install(self.package, "v2", "alice", "task")
        fresh = self.gateway.approve(
            self.bundle, time.time() + 60, contract=self.case["old"]
        )
        self.approval = fresh
        self.assertEqual(len(self.execute(method="renew")), 2)

    def test_base_acl_revocation_applies_at_effect_commit(self):
        self.gateway.set_acl("alice", "export", "local", [])
        with self.assertRaises(PermissionError):
            self.execute()
        self.assertFalse((self.root / "local/public.bin").exists())
        with self.gateway.connect() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM receipts").fetchone()[0], 1
            )

    def test_expired_approval_rejects_before_actual_io(self):
        from unittest.mock import patch

        with patch("driftcert.gateway.time.time", return_value=time.time() + 120):
            with self.assertRaises(PermissionError):
                self.execute()
        self.assertFalse((self.root / "local").exists())

    def test_live_predicate_state_is_application_owned(self):
        self.case["state"] = {"level": 1}
        self.case["new"]["effects"][1]["when"] = {"compare": ["$state.level", "ge", 1]}
        self.package = core.compile_guard(self.case)
        self.bundle = self.gateway.install(self.package, "v2", "alice", "state-task")
        self.approval = self.gateway.approve(self.bundle, time.time() + 60)
        self.gateway.set_state("level", 0)
        with self.assertRaises(PermissionError):
            self.gateway.execute(
                self.bundle,
                self.approval,
                "alice",
                "state-task",
                "v2",
                self.raw,
                self.program,
                state={"level": 1},
            )
        self.assertFalse((self.root / "local").exists())

    def test_full_matrix_exact_regions_and_fresh_workflow(self):
        from driftcert.evaluation import exact_regions

        for method in core.METHODS:
            counts = exact_regions(self.case, method)
            self.assertEqual(sum(counts.values()), 12)
            if method not in ("schema", "no_default_expansion"):
                self.assertEqual(counts["false_safe"], 0, method)
        case = copy.deepcopy(self.case)
        case.update(
            bound_version=1,
            current_version=2,
            principal="alice",
            base_permit=True,
            now=1,
            fresh_approval=dict(
                approved=True,
                version=2,
                principal="alice",
                expires=60,
                contract=self.case["old"],
            ),
        )
        result = core.run_case(case, "pin")
        self.assertFalse(result["reuse"])
        self.assertTrue(result["renewed"])
        self.assertTrue(result["committed"])


if __name__ == "__main__":
    unittest.main()
