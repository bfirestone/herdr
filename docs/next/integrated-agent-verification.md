# Integrated Codex delivery qualification

Codex **remains unqualified**. Server and recipient exact-delivery capabilities
remain absent. This evidence does not close Desktop M2 SC0 or authorize enabling
Send. Ordinary PTY agents are unsupported; there is no PTY prompt fallback.

## Supported candidate and source identity

Candidate: Codex CLI **0.154.0**, native executable and its normal npm launcher.
No other version inherits this evidence. The pinned source is
[`6b9826e3aa83b1a5947db50f4332cb9c65f1b340`](https://github.com/openai/codex/tree/6b9826e3aa83b1a5947db50f4332cb9c65f1b340)
(`rust-v0.154.0`). The inspected checkout was clean.

Local evidence on 2026-09-18: macOS 26.6.2 (25G83), Apple Silicon,
Rust 1.98.1, Python 3.14.7, Node 26.8.1. Installed Herdr and the global Codex executable were
not changed. The native npm package binary SHA-256 is
`4f85982624b3898c8991cb80c0981b2aa71070e3537046c9a95950318a95afcc`;
`@openai/codex/bin/codex.js` SHA-256 is
`61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70`.

## Source audit

Paths below refer to that immutable Codex revision. These findings explain the
boundary; the runtime checks below are separate evidence.

| Surface | Reviewed source and finding |
| --- | --- |
| App-server input | `app-server-transport/src/transport/stdio.rs:43–79` owns a Tokio stdin reader and forwards framed requests on one connection. Herdr invokes only `app-server --listen stdio://`. |
| Fixed thread | `app-server/src/request_processors/turn_processor.rs:366–380, 521–524` parses the supplied UUID and captures that concrete `Arc<CodexThread>`. `core/src/thread_manager.rs:1521–1529` resolves an exact map entry; it has no latest-thread fallback. Removal does not mutate an already captured Arc. |
| Admission acknowledgment | `turn_processor.rs:642–698` awaits `start_or_steer_turn` on that captured object before returning `TurnStartResponse { turn }`. `NotSubmitted` returns an error. The response has no thread ID: Herdr correlates its outstanding request to the fixed thread and validates thread-bearing events. Errors after forwarding remain unknown. |
| Busy/context changes | `core/src/codex_thread.rs:313–319` permits steering an active turn. Herdr therefore admits only one active turn, sends no resume/fork/rollback/reset request, and retires on unexpected context-change events. Tokens and streams never rebind. |
| Shell tools | `core/src/exec.rs:930` selects `RedirectForShellTool`; `core/src/spawn.rs:119–136` maps that policy to null stdin. The `Inherit` variant exists, but full-tree references outside its definition are in `exec/tests/suite/sandbox.rs`, not production callers. |
| Pipe/PTY tools | `utils/pty/src/pipe.rs:158–184` closes unrelated descriptors and selects a new pipe or null stdin. `utils/pty/src/pty.rs:302–355` wires a fresh PTY slave to stdio and closes unrelated FDs. `app-server/src/command_exec.rs:271–295` uses those actual paths with an empty preserved-FD list. |
| Preserved escalation FD | `core/src/tools/runtimes/zsh_fork.rs` takes the escalation FD from `EscalationSession`; `shell-escalation/src/unix/escalate_server.rs:196–212` creates a new datagram socket pair. This is distinct from app-server stdin. It is not a blanket claim that all inherited FDs are closed. |
| Modern hooks | `hooks/src/engine/command_runner.rs:217–224` gives command hooks new stdin/stdout/stderr pipes. `hooks/src/engine/discovery.rs:713–718` requires trusted/managed exact hook identity. The fixture uses one reviewed owned hook's current hash in a process-local CLI layer, never a persisted grant or bypass flag. |
| Legacy notification hook | `hooks/src/legacy_notify.rs:60–66` explicitly uses null stdin/stdout/stderr. This path was source-reviewed; the runtime fixture exercises the modern command hook. |
| MCP stdio | `rmcp-client/src/local_child.rs:20–32` selects fresh pipes. macOS `macos_stdio.rs:150–192` creates separate pipes and dup2 actions; it honors `FD_CLOEXEC`, not `CLOEXEC_DEFAULT`. The fixture enumerates child FDs and excludes the actual provider control read-end identity. |
| Other launchers | `rmcp-client/src/http_headers.rs:442–473`, `core/src/shell_snapshot.rs:287–290`, `utils/sleep-inhibitor/src/linux_inhibitor.rs:206–225`, and `app-server/src/request_processors/feedback_doctor_report.rs:50` explicitly null stdin. `process_exec_processor.rs:310–334` uses fresh pipe/PTY/null paths. |
| npm wrapper | `@openai/codex/bin/codex.js:241–294` spawns one native child with inherited stdio, forwards signals and exits with that child's status; it does not respawn or read/re-route stdin. This launcher-to-provider inheritance is intentional. Both launchers have distinct runtime checks. |

The guarantee trusts the reviewed provider and OS owner. It does not claim to
sandbox arbitrary same-user code or prevent its deliberate access to another
process. No provider control stream is offered to an unrelated shell, tool,
hook, MCP server, or replacement recipient.

## Deterministic Herdr evidence

`src/integrated/helper.rs` runs the production helper loop with controlled child
processes. Its queued-input tests use explicit observer barriers:

1. Initialize the old fixed thread and hold its provider before reading input.
2. Submit A through the production owner. The provider confirms stdin is readable
   without consuming A, establishing real pipe buffering.
3. Revoke the owner or emit a reset; pause only final child cleanup using the
   existing test-only cleanup gate.
4. Initialize a distinct replacement helper/process with a new token in the same
   displayed terminal identity, then release the old process's buffered A.
5. Its late acknowledgment cannot revive the retired owner. The replacement
   observes empty stdin, then accepts a distinct B on its own pipe.

In this forced order the old result is Unknown. Other valid schedules may return
an acknowledgment correlated to the old instance before retirement; they may
never remap it to the replacement. Existing tests also cover partial socket
writes, wrong identity/nonce/PID/UID, replay, disconnect, process exit, overflow,
shared local/remote busy admission, client detach, and approval correlation.
Fixtures do not independently qualify a real provider.

## Real shipped-provider descriptor checks

The opt-in `--provider-fixtures-only` mode exercises the shipped binary, not a
recompiled source library or a simulated receiver. It creates an explicit pipe
for app-server stdin and records its read-end `(device, inode, mode)` before
launch. Each real child reports bounded metadata for every open FD; none may
match that control identity.

- `command/exec` exercises null stdin, a separate streamed pipe, and a fresh PTY.
  Only dedicated child-input bytes may appear in that child. The RPC response
  observer preserves out-of-order responses and correlates every request ID.
- One disposable stdio MCP server observes an actual MCP initialize frame on
  its private stdin. It exposes no tools.
- One disposable SessionStart hook consumes its own hook JSON, records descriptor
  metadata, then returns fixed `continue:false`. The harness requires a stopped
  hook event, matching turn completion and no model/tool output. The fresh empty
  ephemeral thread cannot require history compaction. Source
  `core/src/session/turn.rs:287–289` returns before sampling when that hook stops.
- Initialization failure and normal shutdown close/reap the owned provider. The
  harness checks its observed descendant tree independently of successful receipt
  parsing. No user's process is terminated.

Local macOS results: native and normal npm wrapper passed null/private-pipe/PTY,
hook and MCP checks. Both recorded owned cleanup PASS and a matching stopped
hook without model output. The fixtures create an empty owned `CODEX_HOME`,
remove OpenAI authentication environment and Codex key/token variables, preserve
OS HOME, and require `account/read` to return no account. Both passed in this
unauthenticated configuration. Linux remains unverified until the dedicated
workflow runs successfully.

An attempted supplementary source-library test command,
`cargo test --locked -p codex-hooks -p codex-rmcp-client -p codex-utils-pty --lib`,
failed during setup because the pinned source lockfile required an update under
Rust 1.98.1. No source or lockfile was changed. That setup error is neither a
runtime failure nor substitute runtime evidence.

## Live integrated smoke and manual permission evidence

`scripts/test_integrated_codex.py` requires explicit `--session`, `--scratch`,
`--provider-path` and `--herdr-bin`. The session is `codex-proof-<32 random hex>`;
the scratch basename must be `herdr-codex-<same hex>`, absolute, canonical-parent,
and nonexistent. It validates exact provider version before creating targets.
A separate short owned config/state directory avoids Unix socket path limits.
By default HOME, existing authentication and normal provider approval/sandbox
settings are preserved; `CODEX_SQLITE_HOME` isolates only the new provider state database.

The real Herdr server creates an integrated Codex pane. A harmless text prompt
uses only `agent.prompt_exact`; the harness verifies all returned identities,
provider acknowledgment and final expected response. Prompt bodies never enter
the pane PTY. Consent tests may send only the fixed `allow`/`deny` word to the
helper's rendered consent controls after verifying a complete matching command
card, thread, turn, cwd and exact bounded operation. No persistent approval is
possible through the harness.

Both native and npm launchers passed fixed-thread, matching acknowledgment,
harmless response and cleanup on macOS. Their effective policy was `on-request`
and `workspaceWrite`. Scratch writes occurred without presenting a Herdr consent
card, including a distinct external-disk scratch path outside the one explicit
writable root and a new owned executable with a fixed write-only body. The
reported settings allowed `/tmp` and TMPDIR. **No Herdr approval was sent.**
Those operations do not demonstrate explicit allow/deny and the harness correctly
returned nonzero with `permission_not_requested_deny_scratch_present`.

Normal configured rules or reviewers can allow an operation without a Herdr
click. This observation does not establish a permission bypass, nor does it
satisfy the real permission gate.

The user then approved a stricter policy solely for the disposable test instance.
`--strict-test-policy` creates an owned exec launcher with process-local
`approval_policy="on-request"` and `approvals_reviewer="user"`. It changes no
saved settings, production behavior, authentication, model, or sandbox policy.
The earlier attempted `untrusted` policy was rejected by pinned 0.154.0 before
initialization; that was a setup failure, not a delivery failure. Managed
requirements remain authoritative and the harness never silently falls back.

Both native and normal npm wrapper passed the manual-review test on macOS:
returned policy `on-request`, sandbox `workspaceWrite`, actual matching displayed
approval card for each exact owned operation, Deny prevented its scratch write,
and Allow produced only the expected file content. Fixed thread, matching
acknowledgment, harmless response and owned cleanup all passed. No prompt used
PTY input. Normal-policy no-card observations above remain separate evidence.
The aggregate qualification stays UNVERIFIED pending the platform CI gate.

Example (supply the exact previously validated executables; never auto-install):

```sh
nonce="$(python3 -c 'import uuid; print(uuid.uuid4().hex)')"
python3 scripts/test_integrated_codex.py \
  --session "codex-proof-$nonce" \
  --scratch "/private/tmp/herdr-codex-$nonce" \
  --provider-path /absolute/path/to/pinned/codex \
  --herdr-bin /absolute/path/to/freshly/built/herdr
```

Use `--consent-scratch /canonical/owned/parent/herdr-codex-<same hex>` for a
separate fresh target outside the provider's normal writable roots. Add
`--provider-fixtures-only` for unauthenticated descriptor checks without model
sampling. The explicitly user-approved `--strict-test-policy` option exercises
manual consent for this disposable instance; an actual card is still mandatory.
All harness output is redacted categorical JSON. Successful cleanup removes only
its own temporary directories; provider's normal logging policy still applies.
Host sandbox restrictions on normal provider state must be distinguished from
provider behavior; the local live checks used normal host access without
relaxing Codex's sandbox. Only the explicit manual-review test changes approval
reviewer through its temporary launcher.

## Required gates

`.github/workflows/integrated-agents.yml` pins Rust 1.98.1, Python 3.14 and Node 22
and runs full `just ci`,
`just docs-contract-test`, bootstrap/adversarial fixtures, and pinned native/npm
provider descriptor checks on macOS and Ubuntu. It requests no authentication
secrets and never runs the live model/permission smoke on pull requests.
A workflow definition alone is not Linux or macOS run evidence. Record its exact
run revision and results before closing the platform gate.

Local validation on the candidate change: `RUSTUP_TOOLCHAIN=1.98.1 just ci`
passed (3,511 nextest tests, six skipped, plus repository maintenance and asset
checks). `just docs-contract-test` passed all seven tests. Test fixture commits
used a process-only `commit.gpgsign=false` override; saved Git settings were
unchanged. An earlier restricted-host run failed process-observation and host-key
fixtures; the complete run with normal host access passed. No unrelated failure
was silently waived. The workflow still needs actual macOS/Linux run evidence.
