"""Signed frozen guards, live approvals and mediated real filesystem effects.

Only the reviewed JSON sequence/if/emit IR is executable. Each operation resolves
registered object IDs and sinks beneath the application root before performing
I/O. SQLite serializes epoch/revocation/ACL checks with local commit. A filesystem
write and its SQLite receipt are not a distributed atomic transaction.
"""

import copy
import hashlib
import hmac
import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from . import compiler
from . import semantics as sem


def digest(value):
    return hashlib.sha256(sem.encode(value).encode()).hexdigest()


def signed(payload, key):
    return dict(
        payload=copy.deepcopy(payload),
        signature=hmac.new(
            key, sem.encode(payload).encode(), hashlib.sha256
        ).hexdigest(),
    )


def verified(token, key):
    if not isinstance(token, dict) or set(token) != {"payload", "signature"}:
        raise PermissionError("Malformed signed record")
    expected = hmac.new(
        key, sem.encode(token["payload"]).encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, token["signature"]):
        raise PermissionError("Invalid signature")
    return token["payload"]


class Gateway:
    """Application-owned interpreter and approval ledger; callers supply no paths."""

    def __init__(self, root, database, key, objects, sinks):
        if len(key) < 32:
            raise ValueError("Approval key needs at least 32 bytes")
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.key = key
        self.objects = copy.deepcopy(objects)
        self.sinks = copy.deepcopy(sinks)
        self.database = str(database)
        with self.connect() as db:
            db.executescript("""CREATE TABLE IF NOT EXISTS meta (id INTEGER PRIMARY KEY CHECK(id=1),epoch INTEGER NOT NULL);
            INSERT OR IGNORE INTO meta VALUES(1,0);
            CREATE TABLE IF NOT EXISTS state(name TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS packages(id TEXT PRIMARY KEY,quarantined INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS approvals(id TEXT PRIMARY KEY,payload TEXT NOT NULL,revoked INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS acl(principal TEXT,action TEXT,recipient TEXT,objects TEXT,PRIMARY KEY(principal,action,recipient));
            CREATE TABLE IF NOT EXISTS receipts(id INTEGER PRIMARY KEY,approval TEXT,epoch INTEGER,effect TEXT,committed_at REAL);
            """)
        for identifier, item in self.objects.items():
            if (
                not identifier
                or Path(identifier).name != identifier
                or any(char in identifier for char in ("/", "\\", ":"))
            ):
                raise ValueError("Object identifiers cannot contain path components")
            self.path(item["path"])
        for sink in self.sinks.values():
            self.path(sink)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.database, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            yield db
        finally:
            db.close()

    def path(self, relative):
        result = (self.root / relative).resolve()
        if not result.is_relative_to(self.root):
            raise PermissionError("Path escapes application root")
        return result

    def set_acl(self, principal, action, recipient, objects):
        if not set(objects) <= set(self.objects):
            raise ValueError("Unknown ACL object")
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO acl VALUES(?,?,?,?)",
                (principal, action, recipient, sem.encode(objects)),
            )

    def epoch(self):
        with self.connect() as db:
            return db.execute("SELECT epoch FROM meta WHERE id=1").fetchone()[0]

    def advance_epoch(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE meta SET epoch=epoch+1 WHERE id=1")
            db.commit()
        return self.epoch()

    def install(self, package, version, principal, task):
        """Sign a reviewed package bound to the currently installed implementation."""
        payload = dict(
            package=package,
            version=version,
            principal=principal,
            task=task,
            epoch=self.epoch(),
        )
        with self.connect() as db:
            db.execute(
                "INSERT OR IGNORE INTO packages(id) VALUES(?)", (digest(payload),)
            )
        with self.connect() as db:
            for name, value in package["case"].get("state", {}).items():
                db.execute(
                    "INSERT OR IGNORE INTO state VALUES(?,?)", (name, sem.encode(value))
                )
        return signed(payload, self.key)

    def set_state(self, name, value):
        """Update an application-owned live predicate value under the commit lock."""
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR REPLACE INTO state VALUES(?,?)", (name, sem.encode(value))
            )
            db.commit()

    def live_state(self, db, case):
        names = set(case.get("state", {})) | set(case.get("state_domains", {}))
        return {
            row["name"]: json.loads(row["value"])
            for row in db.execute("SELECT * FROM state")
            if row["name"] in names
        }

    def approve(self, bundle, expires, contract=None):
        """Issue explicit reviewed consent; fresh consent supplies a task contract."""
        installed = verified(bundle, self.key)
        if expires <= time.time():
            raise ValueError("Approval must expire in the future")
        payload = dict(
            bundle=digest(installed),
            version=installed["version"],
            principal=installed["principal"],
            task=installed["task"],
            epoch=installed["epoch"],
            expires=expires,
            contract=copy.deepcopy(contract),
        )
        identifier = digest(payload)
        with self.connect() as db:
            if self.epoch() != installed["epoch"]:
                raise PermissionError("Stale bundle")
            db.execute(
                "INSERT INTO approvals(id,payload) VALUES(?,?)",
                (identifier, sem.encode(payload)),
            )
        return signed(dict(id=identifier, **payload), self.key)

    def revoke(self, approval):
        payload = verified(approval, self.key)
        with self.connect() as db:
            db.execute("UPDATE approvals SET revoked=1 WHERE id=?", (payload["id"],))

    def _authorize(
        self, db, bundle, approval, principal, task, version, raw, state, method
    ):
        installed = verified(bundle, self.key)
        consent = verified(approval, self.key)
        package_status = db.execute(
            "SELECT quarantined FROM packages WHERE id=?", (digest(installed),)
        ).fetchone()
        if package_status is None or package_status[0]:
            raise PermissionError("Package quarantined or uninstalled")
        row = db.execute(
            "SELECT * FROM approvals WHERE id=?", (consent["id"],)
        ).fetchone()
        recorded = {key: value for key, value in consent.items() if key != "id"}
        if row is None or row["revoked"] or row["payload"] != sem.encode(recorded):
            raise PermissionError("Approval revoked or absent")
        if consent["expires"] <= time.time():
            raise PermissionError("Approval expired")
        if (
            principal != installed["principal"]
            or task != installed["task"]
            or consent["bundle"] != digest(installed)
        ):
            raise PermissionError("Principal/task/package binding failed")
        if method != "no_version_binding" and (
            installed["version"] != version
            or installed["epoch"]
            != db.execute("SELECT epoch FROM meta WHERE id=1").fetchone()[0]
        ):
            raise PermissionError("Version or epoch changed")
        package = installed["package"]
        case = package["case"]
        if not sem.equal(state, self.live_state(db, case)):
            raise PermissionError("Live predicate state changed before effect commit")
        if compiler.indices(package, raw, state) is None or not sem.valid_new(
            case, raw, state
        ):
            raise PermissionError("Unsupported input/state")
        if consent["contract"] is None:
            if (
                method == "renew"
                or method == "pin"
                and case.get("old_version") != version
            ):
                raise PermissionError("Fresh approval required")
            if method == "per_call":
                from .symbolic import Model

                model = Model(case)
                point = compiler.indices(package, raw, state)
                if (
                    model.query(
                        {name: [value] for name, value in point.items()},
                        timeout_ms=1000,
                    )["status"]
                    != "UNSAT"
                ):
                    raise PermissionError("Online refinement failed or unresolved")
            elif method == "schema":
                from .schema import compatible

                if not compatible(case, raw):
                    raise PermissionError("Schema mismatch")
            elif not compiler.accepts(package, raw, state):
                raise PermissionError("RECONSENT")
        return installed, consent

    def execute(
        self,
        bundle,
        approval,
        principal,
        task,
        version,
        raw,
        program,
        state=None,
        method="driftcert",
    ):
        """Run actual effects from the restricted program after live authorization."""
        if method not in (
            "driftcert",
            "uniform",
            "global",
            "per_call",
            "pin",
            "renew",
            "schema",
            "no_default_expansion",
            "no_checker",
            "no_gateway",
            "no_version_binding",
        ):
            raise ValueError(method)
        state = state or {}
        installed = verified(bundle, self.key)
        case = installed["package"]["case"]
        with self.connect() as db:
            live = self.live_state(db, case)
        if state and not sem.equal(state, live):
            raise PermissionError("Supplied state is stale")
        state = live
        raw = sem.canonical_raw(case, raw)
        expected = case.get("bindings", {}).get("implementation_digest")
        if (
            method != "no_version_binding"
            and expected is not None
            and expected != digest(program)
        ):
            raise PermissionError("Implementation digest changed")
        args = sem.normalized(raw, case["new"])
        events = []

        def interpret(nodes):
            for node in nodes:
                if set(node) == {"if", "then", "else"}:
                    interpret(
                        node["then"]
                        if sem.condition(node["if"], args, state, raw)
                        else node["else"]
                    )
                elif set(node) == {"emit"}:
                    events.append(
                        {
                            key: sem.value(value, args, state, raw)
                            for key, value in node["emit"].items()
                        }
                    )
                else:
                    raise ValueError("Unsupported executable IR node")

        interpret(program)
        summaries = sem.traces(raw, case["new"], state)
        committed = []
        for event in events:
            with self.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                _, consent = self._authorize(
                    db, bundle, approval, principal, task, version, raw, state, method
                )
                candidate = committed + [event]
                if method != "no_gateway" and not any(
                    len(candidate) <= len(branch)
                    and all(sem.equal(a, b) for a, b in zip(candidate, branch))
                    for branch in summaries
                ):
                    db.execute(
                        "UPDATE packages SET quarantined=1 WHERE id=?",
                        (digest(installed),),
                    )
                    db.commit()
                    raise PermissionError("Actual effect is outside reviewed summary")
                if consent["contract"] is not None and not sem.refines(
                    candidate, consent["contract"], case, args, raw, state
                ):
                    raise PermissionError("Effect exceeds renewed task contract")
                recipient = sem.canonical_recipient(
                    event["recipient"], case.get("recipient_aliases", {})
                )
                acl = db.execute(
                    "SELECT objects FROM acl WHERE principal=? AND action=? AND recipient=?",
                    (principal, event["action"], recipient),
                ).fetchone()
                if acl is None or not sem.subset(event["objects"], json.loads(acl[0])):
                    raise PermissionError("Current base authorization denies effect")
                if type(event.get("objects")) is not list or not all(
                    type(item) is str and item in self.objects
                    for item in event["objects"]
                ):
                    raise PermissionError("Unknown object")
                for identifier in event["objects"]:
                    if not sem.label_leq(
                        self.objects[identifier]["label"],
                        event["label"],
                        case.get("label_order", []),
                    ):
                        raise PermissionError(
                            "Effect label understates trusted object label"
                        )
                if event["action"] == "audit":
                    target = self.path(self.sinks[recipient]) / "audit.jsonl"
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("a", encoding="utf-8") as stream:
                        stream.write(sem.encode(event) + "\n")
                elif event["action"] in ("export", "copy"):
                    destination = self.path(self.sinks[recipient])
                    destination.mkdir(parents=True, exist_ok=True)
                    for identifier in event["objects"]:
                        (destination / (identifier + ".bin")).write_bytes(
                            self.path(self.objects[identifier]["path"]).read_bytes()
                        )
                else:
                    raise ValueError(
                        "No reviewed handler for action: " + event["action"]
                    )
                epoch = db.execute("SELECT epoch FROM meta WHERE id=1").fetchone()[0]
                db.execute(
                    "INSERT INTO receipts(approval,epoch,effect,committed_at) VALUES(?,?,?,?)",
                    (consent["id"], epoch, sem.encode(event), time.time()),
                )
                db.commit()
                committed.append(event)
        if not events:
            with self.connect() as db:
                self._authorize(
                    db, bundle, approval, principal, task, version, raw, state, method
                )
        return committed
