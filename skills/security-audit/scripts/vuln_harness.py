#!/usr/bin/env python3
"""Persistent, model-agnostic orchestration state for the security-audit skill.

This program does not run a model or execute target code.  Codex uses it as a
durable control plane around isolated reconnaissance, hunting, validation, and
verification tasks.  It intentionally depends only on the Python standard
library so a half-finished audit can be resumed without reconstructing state
from a chat transcript.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable
from urllib.parse import urlsplit
import uuid


SCHEMA_VERSION = 1
MAX_JSON_BYTES = 2 * 1024 * 1024
TASK_STAGES = (
    "recon",
    "hunt",
    "validate",
    "verify",
    "gapfill",
    "dedup",
    "trace",
    "feedback",
    "report",
    "fix",
)
TASK_STATUSES = ("queued", "running", "done", "blocked", "failed")
FINDING_KINDS = ("proposal", "validation", "verification")
VERDICTS = ("confirmed", "needs_validation", "rejected")
RUN_STATUSES = ("in_progress", "complete", "incomplete", "failed")
WORKER_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
TASK_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._:/@+-]{0,127}$")
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
FINGERPRINT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]*$")
WINDOWS_RESERVED = re.compile(r"^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$", re.I)
ERROR_RESULT_STATUSES = {
    "error",
    "failed",
    "failure",
    "rate_limited",
    "timeout",
    "overloaded",
    "unavailable",
}
TRANSIENT_TEXT_RE = re.compile(
    r"(?:rate[ -]?limit|temporar(?:y|ily)|service unavailable|timed? out|overloaded|try again)",
    re.I,
)


class HarnessError(RuntimeError):
    """A user-correctable harness error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def utc_after(seconds: int) -> str:
    return (
        datetime.now(timezone.utc) + timedelta(seconds=seconds)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    # ASCII escaping prevents bidi/default-ignorable characters from becoming
    # active terminal controls when CLI JSON is printed or event logs are read.
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def pretty_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def parse_json_text(raw: str, label: str) -> Any:
    encoded = raw.encode("utf-8")
    if len(encoded) > MAX_JSON_BYTES:
        raise HarnessError(f"{label} exceeds the {MAX_JSON_BYTES}-byte limit")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HarnessError(f"{label} is not valid JSON: {exc}") from exc


def load_json_arg(raw: str | None, file_name: str | None, label: str, default: Any = None) -> Any:
    if raw is not None and file_name is not None:
        raise HarnessError(f"provide only one of --{label}-json or --{label}-file")
    if file_name is not None:
        path = Path(file_name)
        try:
            if path.stat().st_size > MAX_JSON_BYTES:
                raise HarnessError(f"{label} file exceeds the {MAX_JSON_BYTES}-byte limit")
            data = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise HarnessError(f"cannot read {label} file {path}: {exc}") from exc
        return parse_json_text(data, label)
    if raw is not None:
        return parse_json_text(raw, label)
    return default


def validate_worker(worker: str) -> None:
    if not WORKER_RE.fullmatch(worker) or WINDOWS_RESERVED.fullmatch(worker):
        raise HarnessError(
            "worker must be a lowercase canonical ID matching "
            "^[a-z0-9][a-z0-9_-]{0,63}$ and not a Windows device name"
        )


def validate_task_key(key: str) -> None:
    if not TASK_KEY_RE.fullmatch(key):
        raise HarnessError("task key is not canonical")


def validate_fingerprint(fingerprint: str) -> None:
    if not FINGERPRINT_RE.fullmatch(fingerprint):
        raise HarnessError("finding fingerprint is not canonical")


def require_bounded_text(value: str, label: str, limit: int = 4096) -> str:
    if not value.strip():
        raise HarnessError(f"{label} cannot be empty")
    if len(value) > limit:
        raise HarnessError(f"{label} exceeds the {limit}-character limit")
    return value


def connect(db_path: str | Path) -> sqlite3.Connection:
    db = Path(db_path).resolve()
    if not db.is_file():
        raise HarnessError(f"harness database does not exist: {db}")
    conn = sqlite3.connect(str(db), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 10000")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        conn.close()
        raise HarnessError(
            f"unsupported database schema {version}; expected {SCHEMA_VERSION}"
        )
    return conn


def one_run(conn: sqlite3.Connection) -> sqlite3.Row:
    rows = conn.execute("SELECT * FROM runs ORDER BY created_at").fetchall()
    if len(rows) != 1:
        raise HarnessError(f"expected exactly one run, found {len(rows)}")
    return rows[0]


def event(
    conn: sqlite3.Connection,
    event_type: str,
    entity_type: str,
    entity_id: str | int | None,
    data: Any,
) -> None:
    run = one_run(conn)
    conn.execute(
        """
        INSERT INTO events(run_id, event_type, entity_type, entity_id, data_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            run["run_id"],
            event_type,
            entity_type,
            None if entity_id is None else str(entity_id),
            canonical_json(data),
            utc_now(),
        ),
    )
    conn.execute("UPDATE runs SET updated_at = ? WHERE run_id = ?", (utc_now(), run["run_id"]))


SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE runs (
  run_id TEXT PRIMARY KEY,
  repo TEXT NOT NULL,
  target TEXT NOT NULL,
  output_dir TEXT NOT NULL,
  source_commit TEXT,
  source_dirty INTEGER NOT NULL CHECK(source_dirty IN (0, 1)),
  profile TEXT NOT NULL CHECK(profile IN ('quick', 'standard', 'deep')),
  scope_json TEXT NOT NULL,
  budget INTEGER CHECK(budget IS NULL OR budget > 0),
  status TEXT NOT NULL CHECK(status IN ('in_progress', 'complete', 'incomplete', 'failed')),
  incomplete_reason TEXT,
  execution_policy TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE tasks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  stage TEXT NOT NULL CHECK(stage IN ('recon','hunt','validate','verify','gapfill','dedup','trace','feedback','report','fix')),
  task_key TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  payload_sha256 TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','running','done','blocked','failed')),
  priority INTEGER NOT NULL DEFAULT 100,
  attempt_count INTEGER NOT NULL DEFAULT 0 CHECK(attempt_count >= 0),
  max_attempts INTEGER NOT NULL DEFAULT 3 CHECK(max_attempts > 0),
  worker TEXT,
  lease_until TEXT,
  not_before TEXT,
  result_json TEXT,
  result_sha256 TEXT,
  error TEXT,
  created_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  updated_at TEXT NOT NULL,
  UNIQUE(run_id, task_key)
);

CREATE INDEX tasks_queue_idx ON tasks(run_id, status, stage, priority, id);

CREATE TABLE finding_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  kind TEXT NOT NULL CHECK(kind IN ('proposal','validation','verification')),
  verdict TEXT NOT NULL CHECK(verdict IN ('confirmed','needs_validation','rejected')),
  record_json TEXT NOT NULL,
  record_sha256 TEXT NOT NULL,
  task_id INTEGER NOT NULL REFERENCES tasks(id),
  worker TEXT NOT NULL,
  parent_record_id INTEGER REFERENCES finding_records(id),
  accepted INTEGER NOT NULL DEFAULT 0 CHECK(accepted IN (0, 1)),
  created_at TEXT NOT NULL,
  UNIQUE(run_id, kind, fingerprint, record_sha256, task_id)
);

CREATE UNIQUE INDEX one_accepted_finding_idx
  ON finding_records(run_id, fingerprint) WHERE accepted = 1;
CREATE INDEX finding_chain_idx ON finding_records(run_id, fingerprint, id);

CREATE TABLE wishlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  request_key TEXT NOT NULL,
  task_id INTEGER REFERENCES tasks(id),
  description TEXT NOT NULL,
  context_json TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('open','resolved','declined')),
  resolution TEXT,
  created_at TEXT NOT NULL,
  resolved_at TEXT,
  UNIQUE(run_id, request_key)
);

CREATE TABLE events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
"""


def git_read(target: Path, args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(target), *args],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def output_is_inside_target(target: Path, output: Path) -> bool:
    try:
        return os.path.commonpath([str(target), str(output)]) == str(target)
    except ValueError:
        return False


def repo_identifier(origin: str | None, target: Path) -> str:
    """Return a useful repository identity without persisting URL credentials."""
    if not origin:
        return target.name
    value = origin.strip()
    if re.match(r"^[^/@:]+@[^:]+:.+", value):
        host, repo_path = value.split(":", 1)
        host = host.rsplit("@", 1)[-1]
        clean_path = repo_path.removesuffix(".git").strip("/")
        return f"{host}/{clean_path}" if clean_path else target.name
    parsed = urlsplit(value)
    if parsed.scheme and parsed.hostname:
        clean_path = parsed.path.removesuffix(".git").strip("/")
        return f"{parsed.hostname}/{clean_path}" if clean_path else parsed.hostname
    return target.name


def normalize_scope(values: list[str] | None) -> list[str]:
    normalized: list[str] = []
    for raw in values or ["."]:
        value = raw.replace("\\", "/").strip()
        if not value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
            raise HarnessError(f"scope must be a nonempty repository-relative path: {raw!r}")
        parts = [part for part in value.split("/") if part not in ("", ".")]
        if any(part == ".." for part in parts):
            raise HarnessError(f"scope must not escape the repository: {raw!r}")
        canonical = "/".join(parts) or "."
        if canonical not in normalized:
            normalized.append(canonical)
    return normalized


def cmd_init(args: argparse.Namespace) -> dict[str, Any]:
    target = Path(args.target).resolve()
    output = Path(args.output).resolve()
    if not target.is_dir():
        raise HarnessError(f"target is not a directory: {target}")
    if output_is_inside_target(target, output) and not args.allow_target_output:
        raise HarnessError(
            "output must be outside the target; pass --allow-target-output only after "
            "verifying the whole output directory is ignored by version control"
        )
    if args.allow_target_output:
        # git check-ignore -q intentionally produces no stdout, so execute it directly.
        try:
            check = subprocess.run(
                ["git", "-C", str(target), "check-ignore", "-q", str(output)],
                check=False,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HarnessError(f"could not verify ignored target output: {exc}") from exc
        if check.returncode != 0:
            raise HarnessError("--allow-target-output requires the output directory to be git-ignored")
    if output.exists() and not output.is_dir():
        raise HarnessError(f"output exists and is not a directory: {output}")
    if output.exists() and any(output.iterdir()):
        raise HarnessError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True)
    db = output / "harness.sqlite3"
    if db.exists():
        raise HarnessError(f"database already exists: {db}")

    source_commit = git_read(target, ["rev-parse", "HEAD"])
    dirty_text = git_read(target, ["status", "--porcelain=v1", "--untracked-files=normal"])
    source_dirty = bool(dirty_text) if dirty_text is not None else False
    origin = git_read(target, ["config", "--get", "remote.origin.url"])
    repo = repo_identifier(origin, target)
    scope = normalize_scope(args.scope)
    run_id = args.run_id or (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    )
    if not RUN_ID_RE.fullmatch(run_id):
        raise HarnessError("run ID must be 1-128 ASCII letters, digits, dots, underscores, colons, or hyphens")
    now = utc_now()

    conn = sqlite3.connect(str(db), timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA_SQL)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.execute(
            """
            INSERT INTO runs(
              run_id, repo, target, output_dir, source_commit, source_dirty,
              profile, scope_json, budget, status, incomplete_reason,
              execution_policy, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'in_progress', NULL, ?, ?, ?)
            """,
            (
                run_id,
                repo,
                str(target),
                str(output),
                source_commit,
                int(source_dirty),
                args.profile,
                canonical_json(scope),
                args.budget,
                "sandboxed-source-and-local-only",
                now,
                now,
            ),
        )
        event(
            conn,
            "run_initialized",
            "run",
            run_id,
            {"profile": args.profile, "scope": scope, "budget": args.budget},
        )
        conn.commit()
    except Exception:
        conn.close()
        try:
            db.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    finally:
        if conn:
            conn.close()
    return {"run_id": run_id, "database": str(db), "output": str(output)}


def task_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "task_key": row["task_key"],
        "stage": row["stage"],
        "status": row["status"],
        "priority": row["priority"],
        "attempt_count": row["attempt_count"],
        "max_attempts": row["max_attempts"],
        "worker": row["worker"],
        "lease_until": row["lease_until"],
        "not_before": row["not_before"],
        "payload": json.loads(row["payload_json"]),
        "result": json.loads(row["result_json"]) if row["result_json"] else None,
        "error": row["error"],
        "created_at": row["created_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "updated_at": row["updated_at"],
    }


def cmd_enqueue(args: argparse.Namespace) -> dict[str, Any]:
    validate_task_key(args.key)
    payload = load_json_arg(args.payload_json, args.payload_file, "payload", default={})
    if not isinstance(payload, dict):
        raise HarnessError("task payload must be a JSON object")
    payload_text = canonical_json(payload)
    payload_hash = sha256_text(payload_text)
    conn = connect(args.db)
    try:
        run = one_run(conn)
        if run["status"] != "in_progress":
            raise HarnessError(f"cannot enqueue tasks while run status is {run['status']}")
        now = utc_now()
        try:
            cursor = conn.execute(
                """
                INSERT INTO tasks(
                  run_id, stage, task_key, payload_json, payload_sha256, status,
                  priority, max_attempts, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?)
                """,
                (
                    run["run_id"],
                    args.stage,
                    args.key,
                    payload_text,
                    payload_hash,
                    args.priority,
                    args.max_attempts,
                    now,
                    now,
                ),
            )
            task_id = cursor.lastrowid
            created = True
            event(conn, "task_enqueued", "task", task_id, {"stage": args.stage, "key": args.key})
        except sqlite3.IntegrityError:
            existing = conn.execute(
                "SELECT * FROM tasks WHERE run_id = ? AND task_key = ?",
                (run["run_id"], args.key),
            ).fetchone()
            if not existing or existing["stage"] != args.stage or existing["payload_sha256"] != payload_hash:
                raise HarnessError(
                    "task key already exists with a different stage or payload; choose a new canonical key"
                )
            task_id = existing["id"]
            created = False
        conn.commit()
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
        return {"created": created, "task": task_to_dict(row)}
    finally:
        conn.close()


def budget_usage(conn: sqlite3.Connection) -> tuple[int, int | None]:
    run = one_run(conn)
    spent = conn.execute("SELECT COALESCE(SUM(attempt_count), 0) FROM tasks").fetchone()[0]
    return int(spent), run["budget"]


def cmd_claim(args: argparse.Namespace) -> dict[str, Any]:
    validate_worker(args.worker)
    if args.lease_seconds < 30 or args.lease_seconds > 86400:
        raise HarnessError("lease seconds must be between 30 and 86400")
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        run = one_run(conn)
        if run["status"] != "in_progress":
            raise HarnessError(f"cannot claim tasks while run status is {run['status']}")
        now = utc_now()
        expired = conn.execute(
            "SELECT id, worker FROM tasks WHERE status = 'running' AND lease_until < ? ORDER BY id",
            (now,),
        ).fetchall()
        for row in expired:
            conn.execute(
                """
                UPDATE tasks SET status = 'queued', worker = NULL, lease_until = NULL,
                  error = 'lease_expired', not_before = ?, updated_at = ? WHERE id = ?
                """,
                (now, now, row["id"]),
            )
            event(conn, "task_lease_expired", "task", row["id"], {"worker": row["worker"]})

        spent, budget = budget_usage(conn)
        if budget is not None and spent >= budget:
            # Preserve any lease-expiry recovery performed above even though a
            # new invocation cannot be funded.
            conn.commit()
            raise HarnessError(f"agent budget exhausted ({spent}/{budget})")

        where = [
            "status = 'queued'",
            "attempt_count < max_attempts",
            "(not_before IS NULL OR not_before <= ?)",
        ]
        params: list[Any] = [now]
        if args.stage:
            where.append("stage = ?")
            params.append(args.stage)
        stage_order = "CASE stage " + " ".join(
            f"WHEN '{stage}' THEN {index}" for index, stage in enumerate(TASK_STAGES, start=1)
        ) + " ELSE 99 END"
        row = conn.execute(
            f"""
            SELECT * FROM tasks WHERE {' AND '.join(where)}
            ORDER BY priority ASC, {stage_order}, id ASC LIMIT 1
            """,
            params,
        ).fetchone()
        if row is None:
            conn.commit()
            return {"task": None, "reclaimed_expired": [item["id"] for item in expired]}

        lease_until = utc_after(args.lease_seconds)
        started_at = row["started_at"] or now
        conn.execute(
            """
            UPDATE tasks SET status = 'running', worker = ?, lease_until = ?,
              attempt_count = attempt_count + 1, started_at = ?, not_before = NULL,
              error = NULL, updated_at = ? WHERE id = ?
            """,
            (args.worker, lease_until, started_at, now, row["id"]),
        )
        event(
            conn,
            "task_claimed",
            "task",
            row["id"],
            {"worker": args.worker, "lease_until": lease_until},
        )
        conn.commit()
        claimed = conn.execute("SELECT * FROM tasks WHERE id = ?", (row["id"],)).fetchone()
        return {"task": task_to_dict(claimed), "reclaimed_expired": [item["id"] for item in expired]}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def running_task(conn: sqlite3.Connection, task_id: int, worker: str) -> sqlite3.Row:
    validate_worker(worker)
    row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise HarnessError(f"task {task_id} does not exist")
    if row["status"] != "running":
        raise HarnessError(f"task {task_id} is {row['status']}, not running")
    if row["worker"] != worker:
        raise HarnessError(f"task {task_id} is leased to {row['worker']!r}, not {worker!r}")
    if row["lease_until"] and row["lease_until"] < utc_now():
        raise HarnessError(f"task {task_id} lease expired; claim it again before writing a result")
    return row


def cmd_heartbeat(args: argparse.Namespace) -> dict[str, Any]:
    if args.lease_seconds < 30 or args.lease_seconds > 86400:
        raise HarnessError("lease seconds must be between 30 and 86400")
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = running_task(conn, args.task_id, args.worker)
        lease_until = utc_after(args.lease_seconds)
        conn.execute(
            "UPDATE tasks SET lease_until = ?, updated_at = ? WHERE id = ?",
            (lease_until, utc_now(), row["id"]),
        )
        event(conn, "task_heartbeat", "task", row["id"], {"lease_until": lease_until})
        conn.commit()
        return {"task_id": row["id"], "lease_until": lease_until}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def result_looks_like_error(result: Any) -> bool:
    if isinstance(result, dict):
        for key in ("status", "type", "state"):
            value = result.get(key)
            if isinstance(value, str) and value.lower() in ERROR_RESULT_STATUSES:
                return True
        if result.get("error") and not any(
            key in result for key in ("decision", "record", "findings", "coverage", "result")
        ):
            return True
        transport_fields = [
            result.get(key) for key in ("output", "text", "message", "content")
            if isinstance(result.get(key), str)
        ]
        if transport_fields and set(result).issubset(
            {"output", "text", "message", "content", "status", "request_id"}
        ) and any(TRANSIENT_TEXT_RE.search(value) for value in transport_fields):
            return True
    if isinstance(result, str) and TRANSIENT_TEXT_RE.search(result):
        return True
    return False


def cmd_complete(args: argparse.Namespace) -> dict[str, Any]:
    result = load_json_arg(args.result_json, args.result_file, "result")
    if result is None:
        raise HarnessError("a JSON result is required")
    if result_looks_like_error(result):
        raise HarnessError(
            "result is error-shaped; record it with fail --transient (or fail) instead of a false success"
        )
    result_text = canonical_json(result)
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = running_task(conn, args.task_id, args.worker)
        now = utc_now()
        conn.execute(
            """
            UPDATE tasks SET status = 'done', result_json = ?, result_sha256 = ?,
              lease_until = NULL, error = NULL, finished_at = ?, updated_at = ? WHERE id = ?
            """,
            (result_text, sha256_text(result_text), now, now, row["id"]),
        )
        event(conn, "task_completed", "task", row["id"], {"worker": args.worker})
        conn.commit()
        return {"task_id": row["id"], "status": "done"}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cmd_fail(args: argparse.Namespace) -> dict[str, Any]:
    require_bounded_text(args.error, "error text")
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = running_task(conn, args.task_id, args.worker)
        now = utc_now()
        requeue = args.transient and row["attempt_count"] < row["max_attempts"]
        if requeue:
            delay = min(3600, 30 * (2 ** max(0, row["attempt_count"] - 1)))
            status = "queued"
            not_before = utc_after(delay)
            worker = None
            finished_at = None
        else:
            status = "failed"
            not_before = None
            worker = row["worker"]
            finished_at = now
        conn.execute(
            """
            UPDATE tasks SET status = ?, worker = ?, lease_until = NULL,
              not_before = ?, error = ?, finished_at = ?, updated_at = ? WHERE id = ?
            """,
            (status, worker, not_before, args.error, finished_at, now, row["id"]),
        )
        event(
            conn,
            "task_requeued" if requeue else "task_failed",
            "task",
            row["id"],
            {"worker": args.worker, "error": args.error, "not_before": not_before},
        )
        conn.commit()
        return {"task_id": row["id"], "status": status, "not_before": not_before}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cmd_block(args: argparse.Namespace) -> dict[str, Any]:
    require_bounded_text(args.reason, "blocker reason")
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = running_task(conn, args.task_id, args.worker)
        now = utc_now()
        conn.execute(
            """
            UPDATE tasks SET status = 'blocked', lease_until = NULL, error = ?,
              finished_at = ?, updated_at = ? WHERE id = ?
            """,
            (args.reason, now, now, row["id"]),
        )
        event(conn, "task_blocked", "task", row["id"], {"worker": args.worker, "reason": args.reason})
        conn.commit()
        return {"task_id": row["id"], "status": "blocked"}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cmd_requeue(args: argparse.Namespace) -> dict[str, Any]:
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        run = one_run(conn)
        if run["status"] != "in_progress":
            raise HarnessError(f"cannot requeue tasks while run status is {run['status']}")
        row = conn.execute("SELECT * FROM tasks WHERE id = ?", (args.task_id,)).fetchone()
        if row is None:
            raise HarnessError(f"task {args.task_id} does not exist")
        if row["status"] not in ("blocked", "failed"):
            raise HarnessError(f"task {args.task_id} is {row['status']}, not blocked or failed")
        max_attempts = args.max_attempts if args.max_attempts is not None else row["max_attempts"]
        if max_attempts <= row["attempt_count"]:
            raise HarnessError(
                f"max attempts must exceed attempts already spent ({row['attempt_count']})"
            )
        now = utc_now()
        conn.execute(
            """
            UPDATE tasks SET status = 'queued', worker = NULL, lease_until = NULL,
              not_before = NULL, result_json = NULL, result_sha256 = NULL,
              error = NULL, finished_at = NULL, max_attempts = ?, updated_at = ?
            WHERE id = ?
            """,
            (max_attempts, now, row["id"]),
        )
        event(
            conn,
            "task_manually_requeued",
            "task",
            row["id"],
            {"prior_status": row["status"], "max_attempts": max_attempts},
        )
        conn.commit()
        return {"task_id": row["id"], "status": "queued", "max_attempts": max_attempts}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cmd_tasks(args: argparse.Namespace) -> dict[str, Any]:
    conn = connect(args.db)
    try:
        where: list[str] = []
        params: list[Any] = []
        if args.stage:
            where.append("stage = ?")
            params.append(args.stage)
        if args.status:
            where.append("status = ?")
            params.append(args.status)
        clause = " WHERE " + " AND ".join(where) if where else ""
        rows = conn.execute(f"SELECT * FROM tasks{clause} ORDER BY priority, id", params).fetchall()
        return {"tasks": [task_to_dict(row) for row in rows]}
    finally:
        conn.close()


def task_for_finding(conn: sqlite3.Connection, task_id: int, expected_stage: str) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
    if row is None:
        raise HarnessError(f"task {task_id} does not exist")
    if row["stage"] != expected_stage:
        raise HarnessError(f"{expected_stage} finding record requires a {expected_stage} task")
    if row["status"] != "done" or not row["worker"]:
        raise HarnessError(f"task {task_id} must be completed by a named worker first")
    return row


def finding_ancestry(conn: sqlite3.Connection, parent_id: int | None) -> list[sqlite3.Row]:
    ancestry: list[sqlite3.Row] = []
    seen: set[int] = set()
    current = parent_id
    while current is not None:
        if current in seen:
            raise HarnessError("finding record ancestry contains a cycle")
        if len(ancestry) >= 100:
            raise HarnessError("finding record ancestry exceeds 100 records")
        seen.add(current)
        row = conn.execute("SELECT * FROM finding_records WHERE id = ?", (current,)).fetchone()
        if row is None:
            raise HarnessError(f"parent finding record {current} does not exist")
        ancestry.append(row)
        current = row["parent_record_id"]
    return ancestry


def validate_finding_record(record: Any) -> tuple[str, str]:
    if not isinstance(record, dict):
        raise HarnessError("finding record must be a JSON object")
    fingerprint = record.get("fingerprint")
    verdict = record.get("verdict")
    if not isinstance(fingerprint, str):
        raise HarnessError("finding record requires a string fingerprint")
    validate_fingerprint(fingerprint)
    if verdict not in VERDICTS:
        raise HarnessError(f"finding verdict must be one of {', '.join(VERDICTS)}")
    return fingerprint, verdict


def cmd_finding_ingest(args: argparse.Namespace) -> dict[str, Any]:
    record = load_json_arg(args.record_json, args.record_file, "record")
    fingerprint, verdict = validate_finding_record(record)
    record_text = canonical_json(record)
    record_hash = sha256_text(record_text)
    expected_stage = {"proposal": "hunt", "validation": "validate", "verification": "verify"}[args.kind]
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        run = one_run(conn)
        task = task_for_finding(conn, args.task_id, expected_stage)
        parent_id = args.parent_record_id
        ancestry = finding_ancestry(conn, parent_id)
        if args.kind == "proposal":
            if parent_id is not None:
                raise HarnessError("proposal records cannot have a parent")
        elif args.kind == "validation":
            if not ancestry or ancestry[0]["kind"] not in ("proposal", "verification"):
                raise HarnessError("validation records require a proposal or replacement-verification parent")
        elif args.kind == "verification":
            if not ancestry or ancestry[0]["kind"] != "validation":
                raise HarnessError("verification records require a validation parent")

        for ancestor in ancestry:
            if ancestor["run_id"] != run["run_id"] or ancestor["fingerprint"] != fingerprint:
                raise HarnessError("finding ancestry must stay in the same run and fingerprint")
            if ancestor["worker"] == task["worker"]:
                raise HarnessError(
                    f"worker {task['worker']!r} already appears in this finding's ancestry; use a fresh worker"
                )

        try:
            cursor = conn.execute(
                """
                INSERT INTO finding_records(
                  run_id, fingerprint, kind, verdict, record_json, record_sha256,
                  task_id, worker, parent_record_id, accepted, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    run["run_id"],
                    fingerprint,
                    args.kind,
                    verdict,
                    record_text,
                    record_hash,
                    task["id"],
                    task["worker"],
                    parent_id,
                    utc_now(),
                ),
            )
            record_id = cursor.lastrowid
            created = True
            event(
                conn,
                "finding_record_ingested",
                "finding_record",
                record_id,
                {"fingerprint": fingerprint, "kind": args.kind, "verdict": verdict},
            )
        except sqlite3.IntegrityError:
            existing = conn.execute(
                """
                SELECT * FROM finding_records
                WHERE run_id = ? AND kind = ? AND fingerprint = ?
                  AND record_sha256 = ? AND task_id = ?
                """,
                (run["run_id"], args.kind, fingerprint, record_hash, task["id"]),
            ).fetchone()
            if existing is None:
                raise
            record_id = existing["id"]
            created = False
        conn.commit()
        return {
            "created": created,
            "record_id": record_id,
            "fingerprint": fingerprint,
            "kind": args.kind,
            "verdict": verdict,
        }
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def finding_to_dict(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "fingerprint": row["fingerprint"],
        "kind": row["kind"],
        "verdict": row["verdict"],
        "record": json.loads(row["record_json"]),
        "record_sha256": row["record_sha256"],
        "task_id": row["task_id"],
        "worker": row["worker"],
        "parent_record_id": row["parent_record_id"],
        "accepted": bool(row["accepted"]),
        "created_at": row["created_at"],
    }


def cmd_finding_accept(args: argparse.Namespace) -> dict[str, Any]:
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        run = one_run(conn)
        row = conn.execute("SELECT * FROM finding_records WHERE id = ?", (args.record_id,)).fetchone()
        if row is None or row["run_id"] != run["run_id"]:
            raise HarnessError(f"finding record {args.record_id} does not exist in this run")
        parent = None
        if row["parent_record_id"] is not None:
            parent = conn.execute(
                "SELECT * FROM finding_records WHERE id = ?", (row["parent_record_id"],)
            ).fetchone()
        if run["profile"] == "quick":
            if row["kind"] != "validation" or parent is None:
                raise HarnessError("quick profile accepts only independently validated records")
        else:
            if row["kind"] != "verification" or parent is None or parent["kind"] != "validation":
                raise HarnessError("standard/deep profiles accept only verification records over validations")
            if row["record_sha256"] != parent["record_sha256"]:
                raise HarnessError(
                    "verification materially replaced the record; validate the replacement with a fresh "
                    "worker, then verify that exact record again before acceptance"
                )
        conn.execute(
            "UPDATE finding_records SET accepted = 0 WHERE run_id = ? AND fingerprint = ?",
            (run["run_id"], row["fingerprint"]),
        )
        conn.execute("UPDATE finding_records SET accepted = 1 WHERE id = ?", (row["id"],))
        event(
            conn,
            "finding_record_accepted",
            "finding_record",
            row["id"],
            {"fingerprint": row["fingerprint"], "verdict": row["verdict"]},
        )
        conn.commit()
        return {"record_id": row["id"], "fingerprint": row["fingerprint"], "accepted": True}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cmd_findings(args: argparse.Namespace) -> dict[str, Any]:
    conn = connect(args.db)
    try:
        where = " WHERE accepted = 1" if args.accepted else ""
        rows = conn.execute(
            f"SELECT * FROM finding_records{where} ORDER BY fingerprint, id"
        ).fetchall()
        return {"findings": [finding_to_dict(row) for row in rows]}
    finally:
        conn.close()


def cmd_wishlist_add(args: argparse.Namespace) -> dict[str, Any]:
    validate_task_key(args.key)
    require_bounded_text(args.description, "wishlist description")
    context = load_json_arg(args.context_json, args.context_file, "context", default={})
    if not isinstance(context, dict):
        raise HarnessError("wishlist context must be a JSON object")
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        run = one_run(conn)
        if args.task_id is not None:
            task = conn.execute("SELECT run_id FROM tasks WHERE id = ?", (args.task_id,)).fetchone()
            if task is None or task["run_id"] != run["run_id"]:
                raise HarnessError(f"task {args.task_id} does not exist in this run")
        try:
            cursor = conn.execute(
                """
                INSERT INTO wishlist(
                  run_id, request_key, task_id, description, context_json, status,
                  resolution, created_at, resolved_at
                ) VALUES (?, ?, ?, ?, ?, 'open', NULL, ?, NULL)
                """,
                (
                    run["run_id"],
                    args.key,
                    args.task_id,
                    args.description,
                    canonical_json(context),
                    utc_now(),
                ),
            )
            item_id = cursor.lastrowid
            created = True
            event(conn, "wishlist_added", "wishlist", item_id, {"key": args.key})
        except sqlite3.IntegrityError:
            existing = conn.execute(
                "SELECT * FROM wishlist WHERE run_id = ? AND request_key = ?",
                (run["run_id"], args.key),
            ).fetchone()
            if (
                existing is None
                or existing["description"] != args.description
                or existing["context_json"] != canonical_json(context)
                or existing["task_id"] != args.task_id
            ):
                raise HarnessError("wishlist key already exists with different content")
            item_id = existing["id"]
            created = False
        conn.commit()
        return {"created": created, "wishlist_id": item_id, "key": args.key}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def cmd_wishlist_resolve(args: argparse.Namespace) -> dict[str, Any]:
    require_bounded_text(args.resolution, "wishlist resolution")
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM wishlist WHERE id = ?", (args.item_id,)).fetchone()
        if row is None:
            raise HarnessError(f"wishlist item {args.item_id} does not exist")
        now = utc_now()
        conn.execute(
            "UPDATE wishlist SET status = ?, resolution = ?, resolved_at = ? WHERE id = ?",
            (args.status, args.resolution, now, row["id"]),
        )
        event(
            conn,
            "wishlist_closed",
            "wishlist",
            row["id"],
            {"status": args.status, "resolution": args.resolution},
        )
        conn.commit()
        return {"wishlist_id": row["id"], "status": args.status}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def wishlist_rows(conn: sqlite3.Connection, status: str | None = None) -> list[dict[str, Any]]:
    if status:
        rows = conn.execute("SELECT * FROM wishlist WHERE status = ? ORDER BY id", (status,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM wishlist ORDER BY id").fetchall()
    return [
        {
            "id": row["id"],
            "request_key": row["request_key"],
            "task_id": row["task_id"],
            "description": row["description"],
            "context": json.loads(row["context_json"]),
            "status": row["status"],
            "resolution": row["resolution"],
            "created_at": row["created_at"],
            "resolved_at": row["resolved_at"],
        }
        for row in rows
    ]


def cmd_wishlist(args: argparse.Namespace) -> dict[str, Any]:
    conn = connect(args.db)
    try:
        return {"wishlist": wishlist_rows(conn, args.status)}
    finally:
        conn.close()


def atomic_write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(contents)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        try:
            os.unlink(temp_name)
        except OSError:
            pass
        raise


def export_run(conn: sqlite3.Connection) -> dict[str, Any]:
    run = one_run(conn)
    output = Path(run["output_dir"])
    spent, budget = budget_usage(conn)
    metadata = {
        "run_id": run["run_id"],
        "repo": run["repo"],
        "target": run["target"],
        "source_ref": {"commit": run["source_commit"], "dirty": bool(run["source_dirty"])},
        "profile": run["profile"],
        "scope_paths": json.loads(run["scope_json"]),
        "budget": budget,
        "agents_spent": spent,
        "execution_policy": run["execution_policy"],
        "selected_companion_files": [],
        "prior_run_paths": [],
        "shared_file_owners": {"canonical": "parent", "database": "harness"},
        "run_status": run["status"],
        "incomplete_reason": run["incomplete_reason"],
        "created_at": run["created_at"],
        "updated_at": run["updated_at"],
    }
    tasks = [task_to_dict(row) for row in conn.execute("SELECT * FROM tasks ORDER BY id")]
    findings = [
        json.loads(row["record_json"])
        for row in conn.execute(
            "SELECT * FROM finding_records WHERE accepted = 1 ORDER BY fingerprint, id"
        )
    ]
    wishlist = wishlist_rows(conn)
    event_rows = conn.execute("SELECT * FROM events ORDER BY seq").fetchall()
    events = "".join(
        canonical_json(
            {
                "seq": row["seq"],
                "event_type": row["event_type"],
                "entity_type": row["entity_type"],
                "entity_id": row["entity_id"],
                "data": json.loads(row["data_json"]),
                "created_at": row["created_at"],
            }
        )
        + "\n"
        for row in event_rows
    )
    atomic_write(output / "run-metadata.json", pretty_json(metadata))
    atomic_write(output / "harness-tasks.json", pretty_json(tasks))
    atomic_write(output / "findings.json", pretty_json(findings))
    atomic_write(output / "wishlist.json", pretty_json(wishlist))
    atomic_write(output / "harness-events.ndjson", events)
    return {
        "output": str(output),
        "files": [
            "run-metadata.json",
            "harness-tasks.json",
            "findings.json",
            "wishlist.json",
            "harness-events.ndjson",
        ],
        "accepted_findings": len(findings),
    }


def cmd_export(args: argparse.Namespace) -> dict[str, Any]:
    conn = connect(args.db)
    try:
        return export_run(conn)
    finally:
        conn.close()


def cmd_set_status(args: argparse.Namespace) -> dict[str, Any]:
    if args.status == "incomplete" and not args.reason:
        raise HarnessError("incomplete status requires --reason")
    if args.status != "incomplete" and args.reason:
        raise HarnessError("--reason is only valid with incomplete status")
    if args.reason:
        require_bounded_text(args.reason, "incomplete reason")
    conn = connect(args.db)
    try:
        conn.execute("BEGIN IMMEDIATE")
        run = one_run(conn)
        if args.status == "complete":
            unfinished = conn.execute(
                "SELECT COUNT(*) FROM tasks WHERE status IN ('queued','running')"
            ).fetchone()[0]
            if unfinished:
                raise HarnessError(f"cannot complete run with {unfinished} queued/running task(s)")
            output = Path(run["output_dir"])
            required_artifacts = (
                "architecture.md",
                "coverage-ledger.json",
                "REPORT.md",
                "FINDINGS-DETAIL.md",
                "NEEDS-VALIDATION.md",
            )
            missing = [name for name in required_artifacts if not (output / name).is_file()]
            if missing:
                raise HarnessError(
                    "cannot complete run before Phase 6 artifacts exist: " + ", ".join(missing)
                )
            invariant_errors = collect_check_errors(conn)
            if invariant_errors:
                raise HarnessError("cannot complete run: " + "; ".join(invariant_errors[:10]))
            export_run(conn)
            skill_dir = Path(__file__).resolve().parent.parent
            commands = (
                ["node", str(skill_dir / "validate-findings.cjs"), str(output / "findings.json")],
                [
                    "node",
                    str(skill_dir / "validate-coverage-ledger.cjs"),
                    str(output / "coverage-ledger.json"),
                ],
            )
            for command in commands:
                ok, detail = run_node_validator(command)
                if not ok:
                    raise HarnessError(
                        f"cannot complete run because validator failed ({' '.join(command)}): {detail}"
                    )
        now = utc_now()
        conn.execute(
            "UPDATE runs SET status = ?, incomplete_reason = ?, updated_at = ? WHERE run_id = ?",
            (args.status, args.reason, now, run["run_id"]),
        )
        event(
            conn,
            "run_status_changed",
            "run",
            run["run_id"],
            {"status": args.status, "reason": args.reason},
        )
        export_run(conn)
        conn.commit()
        return {"run_id": run["run_id"], "status": args.status, "reason": args.reason}
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def status_summary(conn: sqlite3.Connection) -> dict[str, Any]:
    run = one_run(conn)
    task_counts = {
        row["status"]: row["count"]
        for row in conn.execute("SELECT status, COUNT(*) AS count FROM tasks GROUP BY status")
    }
    stage_counts = {
        row["stage"]: row["count"]
        for row in conn.execute("SELECT stage, COUNT(*) AS count FROM tasks GROUP BY stage")
    }
    finding_counts = {
        row["kind"]: row["count"]
        for row in conn.execute("SELECT kind, COUNT(*) AS count FROM finding_records GROUP BY kind")
    }
    spent, budget = budget_usage(conn)
    return {
        "run_id": run["run_id"],
        "status": run["status"],
        "profile": run["profile"],
        "target": run["target"],
        "output": run["output_dir"],
        "source_ref": {"commit": run["source_commit"], "dirty": bool(run["source_dirty"])},
        "task_counts": task_counts,
        "stage_counts": stage_counts,
        "finding_record_counts": finding_counts,
        "accepted_findings": conn.execute(
            "SELECT COUNT(*) FROM finding_records WHERE accepted = 1"
        ).fetchone()[0],
        "open_wishlist": conn.execute(
            "SELECT COUNT(*) FROM wishlist WHERE status = 'open'"
        ).fetchone()[0],
        "agents_spent": spent,
        "budget": budget,
        "updated_at": run["updated_at"],
    }


def cmd_status(args: argparse.Namespace) -> dict[str, Any]:
    conn = connect(args.db)
    try:
        return status_summary(conn)
    finally:
        conn.close()


def collect_check_errors(conn: sqlite3.Connection) -> list[str]:
    errors: list[str] = []
    integrity = conn.execute("PRAGMA integrity_check").fetchall()
    if len(integrity) != 1 or integrity[0][0] != "ok":
        errors.extend(f"sqlite integrity: {row[0]}" for row in integrity)
    for row in conn.execute("PRAGMA foreign_key_check"):
        errors.append(f"foreign key violation: table={row[0]} rowid={row[1]} parent={row[2]}")

    for row in conn.execute("SELECT * FROM tasks ORDER BY id"):
        if sha256_text(row["payload_json"]) != row["payload_sha256"]:
            errors.append(f"task {row['id']}: payload hash mismatch")
        if row["status"] == "running" and (not row["worker"] or not row["lease_until"]):
            errors.append(f"task {row['id']}: running task lacks worker or lease")
        if row["status"] == "done":
            if row["result_json"] is None or row["result_sha256"] is None:
                errors.append(f"task {row['id']}: done task lacks result")
            elif sha256_text(row["result_json"]) != row["result_sha256"]:
                errors.append(f"task {row['id']}: result hash mismatch")

    run = one_run(conn)
    spent, budget = budget_usage(conn)
    if budget is not None and spent > budget:
        errors.append(f"agent budget exceeded: {spent}/{budget}")
    if run["status"] == "complete":
        unfinished = conn.execute(
            "SELECT COUNT(*) FROM tasks WHERE status IN ('queued','running')"
        ).fetchone()[0]
        if unfinished:
            errors.append(f"complete run has {unfinished} unfinished task(s)")

    accepted_by_fingerprint: set[str] = set()
    records = conn.execute("SELECT * FROM finding_records ORDER BY id").fetchall()
    for row in records:
        if sha256_text(row["record_json"]) != row["record_sha256"]:
            errors.append(f"finding record {row['id']}: record hash mismatch")
        try:
            record = json.loads(row["record_json"])
            fingerprint, verdict = validate_finding_record(record)
            if fingerprint != row["fingerprint"] or verdict != row["verdict"]:
                errors.append(f"finding record {row['id']}: indexed fields disagree with JSON")
        except (HarnessError, json.JSONDecodeError) as exc:
            errors.append(f"finding record {row['id']}: invalid JSON record: {exc}")
        try:
            ancestry = finding_ancestry(conn, row["parent_record_id"])
            workers = [row["worker"], *(ancestor["worker"] for ancestor in ancestry)]
            if len(workers) != len(set(workers)):
                errors.append(f"finding record {row['id']}: worker repeats in ancestry")
            if any(ancestor["fingerprint"] != row["fingerprint"] for ancestor in ancestry):
                errors.append(f"finding record {row['id']}: fingerprint changes in ancestry")
        except HarnessError as exc:
            errors.append(f"finding record {row['id']}: {exc}")
        if row["accepted"]:
            if row["fingerprint"] in accepted_by_fingerprint:
                errors.append(f"finding {row['fingerprint']}: more than one accepted record")
            accepted_by_fingerprint.add(row["fingerprint"])
            parent = (
                conn.execute("SELECT * FROM finding_records WHERE id = ?", (row["parent_record_id"],)).fetchone()
                if row["parent_record_id"] is not None
                else None
            )
            if run["profile"] == "quick" and row["kind"] != "validation":
                errors.append(f"finding record {row['id']}: quick acceptance is not a validation")
            if run["profile"] != "quick":
                if row["kind"] != "verification" or parent is None or parent["kind"] != "validation":
                    errors.append(f"finding record {row['id']}: acceptance lacks final verification")
                elif row["record_sha256"] != parent["record_sha256"]:
                    errors.append(f"finding record {row['id']}: accepted verification changed its parent")
    return errors


def run_node_validator(command: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    output = (result.stdout + result.stderr).strip()
    return result.returncode == 0, output


def cmd_check(args: argparse.Namespace) -> dict[str, Any]:
    conn = connect(args.db)
    try:
        errors = collect_check_errors(conn)
        validator_results: list[dict[str, Any]] = []
        if args.validators:
            exported = export_run(conn)
            skill_dir = Path(__file__).resolve().parent.parent
            output = Path(exported["output"])
            commands = [
                ["node", str(skill_dir / "validate-findings.cjs"), str(output / "findings.json")]
            ]
            ledger = output / "coverage-ledger.json"
            if ledger.exists():
                commands.append(["node", str(skill_dir / "validate-coverage-ledger.cjs"), str(ledger)])
            for command in commands:
                ok, detail = run_node_validator(command)
                validator_results.append({"command": command, "ok": ok, "detail": detail})
                if not ok:
                    errors.append(f"validator failed: {' '.join(command)}: {detail}")
        return {"ok": not errors, "errors": errors, "validators": validator_results}
    finally:
        conn.close()


def add_db(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", required=True, help="Path to harness.sqlite3")


def add_json_source(parser: argparse.ArgumentParser, stem: str) -> None:
    parser.add_argument(f"--{stem}-json")
    parser.add_argument(f"--{stem}-file")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Durable control plane for the Codex security-audit vulnerability harness"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    init = sub.add_parser("init", help="Create a new isolated harness run")
    init.add_argument("--target", required=True)
    init.add_argument("--output", required=True)
    init.add_argument("--profile", choices=("quick", "standard", "deep"), default="standard")
    init.add_argument("--scope", action="append")
    init.add_argument("--budget", type=int)
    init.add_argument("--run-id")
    init.add_argument("--allow-target-output", action="store_true")
    init.set_defaults(func=cmd_init)

    enqueue = sub.add_parser("enqueue", help="Idempotently add a durable task")
    add_db(enqueue)
    enqueue.add_argument("--stage", choices=TASK_STAGES, required=True)
    enqueue.add_argument("--key", required=True)
    enqueue.add_argument("--priority", type=int, default=100)
    enqueue.add_argument("--max-attempts", type=int, default=3)
    add_json_source(enqueue, "payload")
    enqueue.set_defaults(func=cmd_enqueue)

    claim = sub.add_parser("claim", help="Atomically lease the next queued task")
    add_db(claim)
    claim.add_argument("--worker", required=True)
    claim.add_argument("--stage", choices=TASK_STAGES)
    claim.add_argument("--lease-seconds", type=int, default=3600)
    claim.set_defaults(func=cmd_claim)

    heartbeat = sub.add_parser("heartbeat", help="Extend a running task lease")
    add_db(heartbeat)
    heartbeat.add_argument("--task-id", type=int, required=True)
    heartbeat.add_argument("--worker", required=True)
    heartbeat.add_argument("--lease-seconds", type=int, default=3600)
    heartbeat.set_defaults(func=cmd_heartbeat)

    complete = sub.add_parser("complete", help="Persist a successful JSON task result")
    add_db(complete)
    complete.add_argument("--task-id", type=int, required=True)
    complete.add_argument("--worker", required=True)
    add_json_source(complete, "result")
    complete.set_defaults(func=cmd_complete)

    fail = sub.add_parser("fail", help="Fail or retry a leased task")
    add_db(fail)
    fail.add_argument("--task-id", type=int, required=True)
    fail.add_argument("--worker", required=True)
    fail.add_argument("--error", required=True)
    fail.add_argument("--transient", action="store_true")
    fail.set_defaults(func=cmd_fail)

    block = sub.add_parser("block", help="Record an unresolved blocker for a leased task")
    add_db(block)
    block.add_argument("--task-id", type=int, required=True)
    block.add_argument("--worker", required=True)
    block.add_argument("--reason", required=True)
    block.set_defaults(func=cmd_block)

    requeue = sub.add_parser("requeue", help="Requeue a blocked or failed task after its blocker is resolved")
    add_db(requeue)
    requeue.add_argument("--task-id", type=int, required=True)
    requeue.add_argument("--max-attempts", type=int)
    requeue.set_defaults(func=cmd_requeue)

    tasks = sub.add_parser("tasks", help="List tasks")
    add_db(tasks)
    tasks.add_argument("--stage", choices=TASK_STAGES)
    tasks.add_argument("--status", choices=TASK_STATUSES)
    tasks.set_defaults(func=cmd_tasks)

    status = sub.add_parser("status", help="Summarize a run")
    add_db(status)
    status.set_defaults(func=cmd_status)

    ingest = sub.add_parser("finding-ingest", help="Append a proposal, validation, or verification record")
    add_db(ingest)
    ingest.add_argument("--kind", choices=FINDING_KINDS, required=True)
    ingest.add_argument("--task-id", type=int, required=True)
    ingest.add_argument("--parent-record-id", type=int)
    add_json_source(ingest, "record")
    ingest.set_defaults(func=cmd_finding_ingest)

    accept = sub.add_parser("finding-accept", help="Accept an independently checked record for export")
    add_db(accept)
    accept.add_argument("--record-id", type=int, required=True)
    accept.set_defaults(func=cmd_finding_accept)

    findings = sub.add_parser("findings", help="List finding records")
    add_db(findings)
    findings.add_argument("--accepted", action="store_true")
    findings.set_defaults(func=cmd_findings)

    wishlist_add = sub.add_parser("wishlist-add", help="Persist a missing dependency or environment request")
    add_db(wishlist_add)
    wishlist_add.add_argument("--key", required=True)
    wishlist_add.add_argument("--task-id", type=int)
    wishlist_add.add_argument("--description", required=True)
    add_json_source(wishlist_add, "context")
    wishlist_add.set_defaults(func=cmd_wishlist_add)

    wishlist_resolve = sub.add_parser("wishlist-resolve", help="Resolve or decline a wishlist item")
    add_db(wishlist_resolve)
    wishlist_resolve.add_argument("--item-id", type=int, required=True)
    wishlist_resolve.add_argument("--status", choices=("resolved", "declined"), required=True)
    wishlist_resolve.add_argument("--resolution", required=True)
    wishlist_resolve.set_defaults(func=cmd_wishlist_resolve)

    wishlist = sub.add_parser("wishlist", help="List wishlist items")
    add_db(wishlist)
    wishlist.add_argument("--status", choices=("open", "resolved", "declined"))
    wishlist.set_defaults(func=cmd_wishlist)

    export = sub.add_parser("export", help="Atomically materialize reviewable run artifacts")
    add_db(export)
    export.set_defaults(func=cmd_export)

    set_status = sub.add_parser("set-status", help="Set a terminal or active run status")
    add_db(set_status)
    set_status.add_argument("--status", choices=RUN_STATUSES, required=True)
    set_status.add_argument("--reason")
    set_status.set_defaults(func=cmd_set_status)

    check = sub.add_parser("check", help="Check database and optional output-validator invariants")
    add_db(check)
    check.add_argument("--validators", action="store_true")
    check.set_defaults(func=cmd_check)

    return parser


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    if getattr(args, "budget", None) is not None and args.budget <= 0:
        parser.error("--budget must be positive")
    if getattr(args, "max_attempts", None) is not None and args.max_attempts <= 0:
        parser.error("--max-attempts must be positive")
    try:
        result = args.func(args)
        if args.command == "check" and not result["ok"]:
            print(pretty_json(result), end="")
            return 1
        print(pretty_json(result), end="")
        return 0
    except HarnessError as exc:
        print(pretty_json({"ok": False, "error": str(exc)}), end="", file=sys.stderr)
        return 2
    except (OSError, sqlite3.Error, ValueError) as exc:
        print(
            pretty_json({"ok": False, "error": f"harness operation failed: {exc}"}),
            end="",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print(pretty_json({"ok": False, "error": "interrupted"}), end="", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
