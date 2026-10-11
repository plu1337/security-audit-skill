# Codex Vulnerability Harness

Use this control plane for a full audit. It turns the six-phase skill into a
resumable queue without making the SQLite database, the model, or any one chat
the security authority. Source evidence and independent verification remain the
authority.

The harness is deliberately small. It implements the Cloudflare article's
recommended starting point—persistent Recon, Hunt, and Validate stages with a
validator that cannot grade its own work—and supports optional Verify, Gapfill,
Dedup, Trace, Feedback, Report, and Fix tasks when scale actually requires them.
Do not add cross-repository tracing or model-based deduplication just because the
stage names exist.

## What the program does

`scripts/vuln_harness.py` provides:

- a SQLite write-ahead-log database under the audit output directory;
- idempotent task keys, atomic claims, expiring leases, retries, and hard agent
  budgets;
- append-only events and content hashes for task payloads, task results, and
  finding records;
- a persistent wishlist for missing sandboxes, fixtures, toolchains, or owner
  context;
- an enforced proposal → independent validation → independent verification
  chain, including a ban on worker reuse within one finding ancestry;
- a gate that rejects a success result shaped like a transport or rate-limit
  error;
- atomic exports of `run-metadata.json`, `harness-tasks.json`, `findings.json`,
  `wishlist.json`, and `harness-events.ndjson`; and
- invariant checks plus the existing findings and coverage-ledger validators.

It does **not** call a model, create a sandbox, execute target code, decide that a
finding is true, generate a patch, or contact GitHub. Codex remains the
orchestrator. The OS-enforced execution boundary in `SKILL.md` still controls all
target-controlled execution.

## Initialize a run

Resolve absolute paths for the skill, target, and output. The output must be
outside the target by default. Then run:

```text
python <skill-dir>/scripts/vuln_harness.py init \
  --target <absolute-target> \
  --output <absolute-new-output> \
  --profile standard
```

Add `--scope <repo-relative-path>` once per scoped path and `--budget <N>` for a
strict total claim budget. `init` prints the database path. Keep that path as
`<db>` for later commands.

`--allow-target-output` is exceptional. The program accepts it only when Git
confirms that the output is ignored. Never use it to bypass the skill's write
isolation rule.

The database is canonical orchestration state. Exported JSON is a reviewable
snapshot. Do not hand-edit the database, task snapshot, event log, wishlist, or
accepted `findings.json`.

## Queue before delegation

Create every task before starting its worker. Use a stable key derived from the
stage and coverage identity; retries reuse the same key and payload.

```text
python <harness> enqueue --db <db> --stage recon \
  --key recon:principals-and-controls --payload-file <payload.json>

python <harness> claim --db <db> --stage recon \
  --worker recon-principals --lease-seconds 3600
```

Prefer `--payload-file` and `--result-file` for nontrivial JSON. This avoids shell
quoting changing prompts or evidence. Payloads are JSON objects and should carry:

- exact target, output, scope, and source-ref facts needed by the assignment;
- assigned coverage IDs or reconnaissance role;
- repository-relative starting paths;
- copied prompt blocks required by `HUNTING.md` or
  `VALIDATION-AND-REPORTING.md`;
- the worker's unique scratch path and retained-artifact allowlist; and
- explicit exclusions and prior-record context.

The worker ID is a lowercase filesystem-safe identifier. The ID persisted by the
claim must be the same ID used in the Codex assignment and completion command.

## Map tasks to Codex workers

When Codex delegation is available, the parent follows this loop:

1. Enqueue and atomically claim a task.
2. Start one isolated worker with only that task's payload and the minimum source
   context. A hunter never receives another hunter's speculation as fact.
3. Keep independent stages on fresh workers. A validator must not be the hunter;
   a final verifier must be neither.
4. If work lasts near the lease boundary, extend it:

   ```text
   python <harness> heartbeat --db <db> --task-id <id> \
     --worker <worker-id> --lease-seconds 3600
   ```

5. Persist the returned JSON immediately:

   ```text
   python <harness> complete --db <db> --task-id <id> \
     --worker <worker-id> --result-file <result.json>
   ```

6. On a real transient failure, do not record a false success:

   ```text
   python <harness> fail --db <db> --task-id <id> \
     --worker <worker-id> --error <bounded-error-summary> --transient
   ```

7. For an unresolved dependency, block the task and add one idempotent wishlist
   item with the exact condition needed to resume.

The claim command requeues expired leases before selecting work. After a crash,
inspect `status` and `tasks`; do not reconstruct the queue from memory. A retry
increments the hard budget because it is another agent invocation.

If delegation is unavailable, keep the run incomplete rather than allowing one
context to impersonate independent workers.

## Stage progression

Use these minimum gates:

1. **Recon** — run the four reconnaissance roles in `RECONNAISSANCE.md`, synthesize
   `architecture.md`, seed `coverage-ledger.json`, and run its validator. Persist
   each role as a separate `recon` task.
2. **Hunt** — enqueue deterministic coverage assignments. Claim each assignment
   for a fresh hunter, archive its exact structured result, update the parent-owned
   ledger, and ingest every proposed record.
3. **Validate** — enqueue one task per stable fingerprint. A fresh worker tries to
   disprove the proposal and returns a complete schema-shaped record.
4. **Verify** — for `standard` and `deep`, enqueue one final record-verification
   task per validated record. `quick` intentionally combines this with Validate.
5. **Report** — accept only eligible records, export, run deterministic validators,
   then derive prose reports from accepted JSON and the ledger.

`gapfill`, `dedup`, `trace`, and `feedback` are queue types, not mandatory ceremony:

- Use `gapfill` when the coverage critic finds an empty area × attack-class cell.
- Add deterministic candidate selection before an agent-based `dedup` task. Do not
  compare every pair with a model.
- Use `trace` only when more than one repository matters and a source-backed
  dependency graph exists.
- Use `feedback` for recurring validation failures or shallow runs, never to
  rewrite completed evidence.

The `fix` stage is separate from discovery. It requires explicit user authority
to modify source and never merges a change. A clean targeted fail→pass regression
test is the minimum auto-cleanup gate.

## Persist the finding chain

After a hunter task is `done`, store its schema-shaped proposal:

```text
python <harness> finding-ingest --db <db> --kind proposal \
  --task-id <hunt-task-id> --record-file <record.json>
```

After a fresh Validate task, link the independently decided record to the proposal:

```text
python <harness> finding-ingest --db <db> --kind validation \
  --task-id <validate-task-id> --parent-record-id <proposal-record-id> \
  --record-file <record.json>
```

For `quick`, that validation record may be accepted. For `standard` and `deep`, a
fresh Verify task must return the exact record it verifies:

```text
python <harness> finding-ingest --db <db> --kind verification \
  --task-id <verify-task-id> --parent-record-id <validation-record-id> \
  --record-file <record.json>

python <harness> finding-accept --db <db> --record-id <eligible-record-id>
```

The harness rejects self-validation and any worker reused in the record ancestry.
It also rejects a final verification that silently changes the record. If a final
verifier returns a material replacement, ingest it but do not accept it. Enqueue a
fresh Validate task with that verification record as its parent, then a fresh
Verify task over the resulting validation. Acceptance requires the last verifier
to return the exact validated bytes.

Fingerprint identity follows the source-derived root cause, not wording, verdict,
severity, or stage. One accepted record per fingerprint is exported.

## Wishlist

Use the wishlist for a precise missing dependency that a person or later run can
supply, not for vague future research:

```text
python <harness> wishlist-add --db <db> \
  --key env:freebsd-vm --task-id <id> \
  --description "Disposable FreeBSD VM needed for the bounded parser check" \
  --context-file <context.json>
```

The context should say why the item is decisive, the safe configuration, expected
input/output, and which exact task to requeue. Do not put credentials or ambient
environment values in it.

After the dependency is safely supplied, resolve the wishlist item and explicitly
requeue the blocked task. If a failed task already consumed its attempt limit,
raise that limit to a deliberate new ceiling:

```text
python <harness> wishlist-resolve --db <db> --item-id <wishlist-id> \
  --status resolved --resolution <bounded-resolution-summary>
python <harness> requeue --db <db> --task-id <id> --max-attempts <new-ceiling>
```

## Export, validate, and stop

At useful checkpoints and before reporting:

```text
python <harness> export --db <db>
python <harness> check --db <db> --validators
```

`check --validators` always validates accepted `findings.json`; it also validates
`coverage-ledger.json` when present. On Windows, the bundled validators use a
regular-file handle plus before/during/after identity checks because Node does not
expose POSIX no-follow flags. The files remain parent-owned; target-controlled
processes must never receive the output directory.

Finish in exactly one honest state:

```text
python <harness> set-status --db <db> --status complete
```

or:

```text
python <harness> set-status --db <db> --status incomplete \
  --reason <exact-machine-readable-or-bounded-text-reason>
```

`complete` is refused while tasks remain queued or running, before all Phase 6
artifacts exist, or when either deterministic validator fails. Blocked and failed
tasks may remain only when their coverage consequences are explicit in the ledger
and report. The status command exports the terminal snapshot; rerun
`check --validators` as the final handoff check.

Never call a run vulnerability-free. Report the source ref, profile, scope,
unresolved candidates, blocked tasks, open wishlist items, deferred coverage, and
the fact that repeated runs can find additional bugs.
