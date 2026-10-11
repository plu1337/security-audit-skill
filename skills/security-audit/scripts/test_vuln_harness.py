#!/usr/bin/env python3
"""End-to-end tests for vuln_harness.py using only the standard library."""

from __future__ import annotations

import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("vuln_harness.py")


class HarnessCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.output = self.root / "audit-output"
        self.target.mkdir()
        (self.target / "src").mkdir()
        (self.target / "src" / "app.py").write_text("def run(value):\n    return value\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def cli(self, *args: object, expected: int = 0) -> dict:
        command = [sys.executable, str(SCRIPT), *(str(arg) for arg in args)]
        result = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(
            result.returncode,
            expected,
            msg=f"command: {command}\nstdout: {result.stdout}\nstderr: {result.stderr}",
        )
        stream = result.stdout if result.stdout.strip() else result.stderr
        return json.loads(stream)

    def init(self, profile: str = "standard", budget: int | None = None) -> Path:
        args: list[object] = [
            "init",
            "--target",
            self.target,
            "--output",
            self.output,
            "--profile",
            profile,
            "--run-id",
            "test-run",
        ]
        if budget is not None:
            args.extend(["--budget", budget])
        result = self.cli(*args)
        return Path(result["database"])

    def add_and_finish_task(self, db: Path, stage: str, key: str, worker: str) -> int:
        added = self.cli(
            "enqueue",
            "--db",
            db,
            "--stage",
            stage,
            "--key",
            key,
            "--payload-json",
            json.dumps({"purpose": key}),
        )
        task_id = added["task"]["id"]
        claimed = self.cli("claim", "--db", db, "--stage", stage, "--worker", worker)
        self.assertEqual(claimed["task"]["id"], task_id)
        self.cli(
            "complete",
            "--db",
            db,
            "--task-id",
            task_id,
            "--worker",
            worker,
            "--result-json",
            json.dumps({"ok": True, "task": key}),
        )
        return task_id

    @staticmethod
    def rejected_record(reason: str = "The visible guard rejects the input.") -> dict:
        return {
            "verdict": "rejected",
            "fingerprint": "src/app.py:run:identity-claim",
            "title": "Identity claim is blocked by the visible guard",
            "description": "The proposed lower-trust path does not reach a protected effect.",
            "claimed_root_cause": "The proposal claimed that run accepted an unauthorized value.",
            "trace": [
                {
                    "kind": "entrypoint",
                    "file": "src/app.py",
                    "line": 1,
                    "scope": "run",
                    "description": "The local function receives the proposed value.",
                }
            ],
            "evidence": [
                {
                    "file": "src/app.py",
                    "line": 1,
                    "description": "The source does not perform the claimed privileged action.",
                }
            ],
            "reason": reason,
        }

    def test_standard_flow_requires_independent_validation_and_verification(self) -> None:
        db = self.init()
        hunt_task = self.add_and_finish_task(db, "hunt", "hunt:identity", "hunter-1")
        record = self.rejected_record()
        proposal = self.cli(
            "finding-ingest",
            "--db",
            db,
            "--kind",
            "proposal",
            "--task-id",
            hunt_task,
            "--record-json",
            json.dumps(record),
        )

        validate_task = self.add_and_finish_task(db, "validate", "validate:identity", "validator-1")
        validation = self.cli(
            "finding-ingest",
            "--db",
            db,
            "--kind",
            "validation",
            "--task-id",
            validate_task,
            "--parent-record-id",
            proposal["record_id"],
            "--record-json",
            json.dumps(record),
        )

        verify_task = self.add_and_finish_task(db, "verify", "verify:identity", "verifier-1")
        verification = self.cli(
            "finding-ingest",
            "--db",
            db,
            "--kind",
            "verification",
            "--task-id",
            verify_task,
            "--parent-record-id",
            validation["record_id"],
            "--record-json",
            json.dumps(record),
        )
        accepted = self.cli(
            "finding-accept", "--db", db, "--record-id", verification["record_id"]
        )
        self.assertTrue(accepted["accepted"])

        exported = self.cli("export", "--db", db)
        findings = json.loads((Path(exported["output"]) / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(findings, [record])
        checked = self.cli("check", "--db", db, "--validators")
        self.assertTrue(checked["ok"])
        self.assertTrue(checked["validators"])

    def test_same_worker_cannot_validate_its_own_proposal(self) -> None:
        db = self.init()
        hunt_task = self.add_and_finish_task(db, "hunt", "hunt:self-grade", "worker-1")
        proposal = self.cli(
            "finding-ingest",
            "--db",
            db,
            "--kind",
            "proposal",
            "--task-id",
            hunt_task,
            "--record-json",
            json.dumps(self.rejected_record()),
        )
        validate_task = self.add_and_finish_task(db, "validate", "validate:self-grade", "worker-1")
        error = self.cli(
            "finding-ingest",
            "--db",
            db,
            "--kind",
            "validation",
            "--task-id",
            validate_task,
            "--parent-record-id",
            proposal["record_id"],
            "--record-json",
            json.dumps(self.rejected_record()),
            expected=2,
        )
        self.assertIn("fresh worker", error["error"])

    def test_error_shaped_success_is_rejected_and_can_be_retried(self) -> None:
        db = self.init()
        added = self.cli(
            "enqueue",
            "--db",
            db,
            "--stage",
            "recon",
            "--key",
            "recon:transient",
            "--payload-json",
            "{}",
        )
        task_id = added["task"]["id"]
        self.cli("claim", "--db", db, "--worker", "recon-1")
        error = self.cli(
            "complete",
            "--db",
            db,
            "--task-id",
            task_id,
            "--worker",
            "recon-1",
            "--result-json",
            json.dumps({"status": "error", "error": "rate limit; try again"}),
            expected=2,
        )
        self.assertIn("error-shaped", error["error"])
        retry = self.cli(
            "fail",
            "--db",
            db,
            "--task-id",
            task_id,
            "--worker",
            "recon-1",
            "--error",
            "rate limited",
            "--transient",
        )
        self.assertEqual(retry["status"], "queued")
        self.assertIsNotNone(retry["not_before"])

    def test_blocked_task_can_be_requeued_after_dependency_resolution(self) -> None:
        db = self.init()
        added = self.cli(
            "enqueue",
            "--db",
            db,
            "--stage",
            "hunt",
            "--key",
            "hunt:needs-vm",
            "--payload-json",
            "{}",
        )
        task_id = added["task"]["id"]
        self.cli("claim", "--db", db, "--worker", "hunter-1")
        self.cli(
            "block",
            "--db",
            db,
            "--task-id",
            task_id,
            "--worker",
            "hunter-1",
            "--reason",
            "missing disposable VM",
        )
        requeued = self.cli("requeue", "--db", db, "--task-id", task_id)
        self.assertEqual(requeued["status"], "queued")
        claimed = self.cli("claim", "--db", db, "--worker", "hunter-2")
        self.assertEqual(claimed["task"]["id"], task_id)

    def test_budget_is_a_hard_claim_limit(self) -> None:
        db = self.init(budget=1)
        for key in ("recon:first", "recon:second"):
            self.cli(
                "enqueue",
                "--db",
                db,
                "--stage",
                "recon",
                "--key",
                key,
                "--payload-json",
                "{}",
            )
        first = self.cli("claim", "--db", db, "--worker", "recon-1")
        self.cli(
            "complete",
            "--db",
            db,
            "--task-id",
            first["task"]["id"],
            "--worker",
            "recon-1",
            "--result-json",
            '{"ok":true}',
        )
        error = self.cli("claim", "--db", db, "--worker", "recon-2", expected=2)
        self.assertIn("budget exhausted", error["error"])

    def test_concurrent_claims_are_atomic(self) -> None:
        db = self.init()
        for key in ("hunt:first", "hunt:second"):
            self.cli(
                "enqueue",
                "--db",
                db,
                "--stage",
                "hunt",
                "--key",
                key,
                "--payload-json",
                "{}",
            )
        commands = [
            [
                sys.executable,
                str(SCRIPT),
                "claim",
                "--db",
                str(db),
                "--stage",
                "hunt",
                "--worker",
                worker,
            ]
            for worker in ("hunter-a", "hunter-b")
        ]
        processes = [
            subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            for command in commands
        ]
        outputs = [process.communicate(timeout=10) for process in processes]
        self.assertTrue(all(process.returncode == 0 for process in processes), outputs)
        claimed_ids = {json.loads(stdout)["task"]["id"] for stdout, _ in outputs}
        self.assertEqual(len(claimed_ids), 2)

    def test_expired_lease_recovery_persists_when_budget_is_exhausted(self) -> None:
        db = self.init(budget=1)
        added = self.cli(
            "enqueue",
            "--db",
            db,
            "--stage",
            "recon",
            "--key",
            "recon:expired",
            "--payload-json",
            "{}",
        )
        task_id = added["task"]["id"]
        self.cli("claim", "--db", db, "--worker", "recon-1")
        connection = sqlite3.connect(db)
        try:
            connection.execute(
                "UPDATE tasks SET lease_until = '2000-01-01T00:00:00Z' WHERE id = ?", (task_id,)
            )
            connection.commit()
        finally:
            connection.close()
        error = self.cli("claim", "--db", db, "--worker", "recon-2", expected=2)
        self.assertIn("budget exhausted", error["error"])
        tasks = self.cli("tasks", "--db", db)
        self.assertEqual(tasks["tasks"][0]["status"], "queued")
        self.assertEqual(tasks["tasks"][0]["error"], "lease_expired")

    def test_enqueue_and_wishlist_are_idempotent(self) -> None:
        db = self.init(profile="quick")
        first = self.cli(
            "enqueue",
            "--db",
            db,
            "--stage",
            "recon",
            "--key",
            "recon:architecture",
            "--payload-json",
            '{"scope":"."}',
        )
        second = self.cli(
            "enqueue",
            "--db",
            db,
            "--stage",
            "recon",
            "--key",
            "recon:architecture",
            "--payload-json",
            '{"scope":"."}',
        )
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        self.assertEqual(first["task"]["id"], second["task"]["id"])

        wish1 = self.cli(
            "wishlist-add",
            "--db",
            db,
            "--key",
            "env:freebsd-vm",
            "--description",
            "A disposable FreeBSD VM is needed for a bounded local check.",
            "--context-json",
            '{"network":"disabled"}',
        )
        wish2 = self.cli(
            "wishlist-add",
            "--db",
            db,
            "--key",
            "env:freebsd-vm",
            "--description",
            "A disposable FreeBSD VM is needed for a bounded local check.",
            "--context-json",
            '{"network":"disabled"}',
        )
        self.assertTrue(wish1["created"])
        self.assertFalse(wish2["created"])

    def test_cli_escapes_unicode_format_controls(self) -> None:
        db = self.init()
        command = [
            sys.executable,
            str(SCRIPT),
            "wishlist-add",
            "--db",
            str(db),
            "--key",
            "context:format-control",
            "--description",
            "untrusted\u202etext",
            "--context-json",
            "{}",
        ]
        added = subprocess.run(command, check=False, capture_output=True, text=True, encoding="utf-8")
        self.assertEqual(added.returncode, 0, added.stderr)
        listed = subprocess.run(
            [sys.executable, str(SCRIPT), "wishlist", "--db", str(db)],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertNotIn("\u202e", listed.stdout)
        self.assertIn("\\u202e", listed.stdout)

    def test_output_inside_target_is_rejected_by_default(self) -> None:
        inside = self.target / "audit-output"
        error = self.cli(
            "init",
            "--target",
            self.target,
            "--output",
            inside,
            expected=2,
        )
        self.assertIn("outside the target", error["error"])

    def test_incomplete_status_exports_the_exact_reason(self) -> None:
        db = self.init()
        result = self.cli(
            "set-status",
            "--db",
            db,
            "--status",
            "incomplete",
            "--reason",
            "sandbox_unavailable",
        )
        self.assertEqual(result["status"], "incomplete")
        metadata = json.loads((self.output / "run-metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["run_status"], "incomplete")
        self.assertEqual(metadata["incomplete_reason"], "sandbox_unavailable")

    def test_complete_status_requires_phase_six_artifacts(self) -> None:
        db = self.init()
        error = self.cli(
            "set-status", "--db", db, "--status", "complete", expected=2
        )
        self.assertIn("Phase 6 artifacts", error["error"])

    def test_complete_status_runs_validators_and_exports_terminal_snapshot(self) -> None:
        db = self.init()
        (self.output / "architecture.md").write_text("# Architecture\n\nEmpty fixture target.\n", encoding="utf-8")
        (self.output / "coverage-ledger.json").write_text("[]\n", encoding="utf-8")
        (self.output / "REPORT.md").write_text("# Report\n\nNo material surface in fixture.\n", encoding="utf-8")
        (self.output / "FINDINGS-DETAIL.md").write_text("# Finding details\n\nNone.\n", encoding="utf-8")
        (self.output / "NEEDS-VALIDATION.md").write_text("# Needs validation\n\nNone.\n", encoding="utf-8")
        completed = self.cli("set-status", "--db", db, "--status", "complete")
        self.assertEqual(completed["status"], "complete")
        metadata = json.loads((self.output / "run-metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["run_status"], "complete")
        checked = self.cli("check", "--db", db, "--validators")
        self.assertTrue(checked["ok"])

    def test_scope_cannot_escape_target(self) -> None:
        error = self.cli(
            "init",
            "--target",
            self.target,
            "--output",
            self.output,
            "--scope",
            "../other",
            expected=2,
        )
        self.assertIn("must not escape", error["error"])

    def test_remote_credentials_are_not_persisted(self) -> None:
        initialized = subprocess.run(
            ["git", "init", str(self.target)], check=False, capture_output=True, text=True
        )
        if initialized.returncode != 0:
            self.skipTest("git is unavailable")
        subprocess.run(
            [
                "git",
                "-C",
                str(self.target),
                "remote",
                "add",
                "origin",
                "https://audit-user:secret-token@github.com/example/security-target.git",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        db = self.init()
        self.cli("export", "--db", db)
        metadata = json.loads((self.output / "run-metadata.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["repo"], "github.com/example/security-target")
        self.assertNotIn("secret-token", json.dumps(metadata))

    def test_material_verification_replacement_requires_another_cycle(self) -> None:
        db = self.init()
        original = self.rejected_record()
        proposal_task = self.add_and_finish_task(db, "hunt", "hunt:replace", "hunter-1")
        proposal = self.cli(
            "finding-ingest",
            "--db",
            db,
            "--kind",
            "proposal",
            "--task-id",
            proposal_task,
            "--record-json",
            json.dumps(original),
        )
        validation_task = self.add_and_finish_task(db, "validate", "validate:replace", "validator-1")
        validation = self.cli(
            "finding-ingest",
            "--db",
            db,
            "--kind",
            "validation",
            "--task-id",
            validation_task,
            "--parent-record-id",
            proposal["record_id"],
            "--record-json",
            json.dumps(original),
        )
        replacement = self.rejected_record("A materially different rejection rationale.")
        verification_task = self.add_and_finish_task(db, "verify", "verify:replace", "verifier-1")
        verification = self.cli(
            "finding-ingest",
            "--db",
            db,
            "--kind",
            "verification",
            "--task-id",
            verification_task,
            "--parent-record-id",
            validation["record_id"],
            "--record-json",
            json.dumps(replacement),
        )
        error = self.cli(
            "finding-accept",
            "--db",
            db,
            "--record-id",
            verification["record_id"],
            expected=2,
        )
        self.assertIn("materially replaced", error["error"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
