# Integrated Codex delivery qualification

This source enables the version-1 exact-prompt capability for the owned Codex
0.154.0 launch on macOS and Linux. Server support is separate from recipient
readiness: a recipient appears only after authenticated initialization and fixed
thread creation; it is ready only while idle with admission capacity. Ordinary
PTY agents are unsupported; there is no PTY prompt fallback.

**Codex T3 is qualified within the boundaries below** by the combined source
audit, deterministic tests, independent public API evaluation, native/npm live
smoke and actual platform CI. The qualified code revision is
`f84d5dd80df7dfbac9079486ad5836d343901d9d`. Claude implementation is present but its real-provider proof remains
open, so this does not complete Desktop M2 SC0 or the whole M2 milestone.

## Claude qualification checkpoint — unqualified

Claude exact-prompt capability remains absent. Remote admission still refuses
Claude recipients; the changes below support continued qualification work and
do not establish T5 acceptance or reuse Codex platform proof for Claude.

The audited native macOS arm64 CLI is 2.1.276 (embedded source revision
`bc0a4292e0472d227ceecb07d892ab1a777a4926`, binary SHA-256
`9de364db11a410d53cbbb0f6b1f18c66c90053efc9a63370072856d10db66329`).
The SDK declarations are 0.3.276, SHA-256
`6c0c98e0f3b269d7b811fc0e92607d73633d263c067eb72cd3527fa02fc7f213`.
Retained source slices and actual run reports belong to T5 source revisions 1
and 2, implementation attempt 1 in each; they are evidence for this checkpoint, not a completed
cross-platform qualification.

Source-backed admission and protocol defects now have regression coverage. Claude parses slash
commands after JavaScript `trim()`, which removes U+FEFF. Admission now rejects
leading slash commands behind BOM and mixed whitespace before either local or
remote writes, while preserving admitted text bytes. This closes the observed
ordinary-text route to `/clear`. The pinned print envelope can drop the internal
`conversation_reset` event, so a late mismatched replay or parser reset handler
alone cannot establish zero delivery. The remaining context-control and relaunch
reachability audit is still required.

Configured SessionStart/Setup hooks can emit lifecycle notifications before the
initialize reply. The parser now accepts their validated schema only in the
original session. These events do not confirm readiness, settle consent, change
pending input, or revive a revoked owner; hook output is not projected. Invalid
context and malformed lifecycle frames still fail closed. The actual CLI also emits
`command_lifecycle` notifications. Validated queue/start/completion/cancellation
states are informational: they cannot substitute for the matching input replay,
settle a consent card, or change admission state.

`scripts/test_integrated_claude.py` provides an explicit opt-in raw prerequisite
probe, with an init-only mode and deterministic safety tests included in the
Rust integration gate. It requires a fresh named scratch/session target, keeps
existing authentication and defaults to unchanged permission policy, bounds I/O and waits, and reports
fixed categories and field types instead of raw provider messages. Process
inspection precedes launch. Cleanup always attempts to reap the owned provider
even if closing stdin fails; child observations retain birth identity and
separate living and zombie counts. Observed disappearance is not proof that the
harness reaped every descendant. The report always sets `qualification: false`.

Actual macOS observations established initialize/version and a matching raw
text replay. The unchanged-policy Write probe then created its exact owned
`deny.txt` without requesting consent; it failed `consent_not_requested` and
never reached the Allow case. This is not Deny proof. That run observed 57
children and ended with zero observed living or zombie children, no harness
cleanup errors, and no supervisor survivors or emergency cleanup. Earlier failed
initialization and unavailable-inspection attempts remain retained separately;
supervisor cleanup does not turn uncertain harness cleanup into a pass.

The subsequent real raw protocol probe passed matching Allow/Deny after the
user authorized a stricter disposable Claude policy. The explicit
`--manual-write-policy` probe option
adds default mode and a Write ask rule, verifies effective default mode before
text, and preserves saved rules and hooks. Pinned source checks deny before ask
before allow, and routes PreToolUse hook approvals through the permission
pipeline when an ask rule applies. The run observed two matching consent requests
and response echoes, three completed turns, absent denied output and exact
allowed output. It observed 78 children and ended with zero living or zombie
children, no cleanup errors, and no supervisor survivors or emergency cleanup.
This proves the raw prerequisite. No saved policy has been changed.

Subsequent actual macOS prerequisites passed independently:

- Owned SessionStart hook and MCP descriptor receipts each contained three FDs
  and no match to the private provider input. The observation control proved that
  the captured read-end identity survived inheritance and distinguished separate
  pipes. A prior Darwin signed-device-number validation failure remains retained.
- One model-requested Bash metadata command produced three observed FDs with no
  provider-input match, matching replay and an actual scoped consent request.
  The process-local probe added default mode and an ask rule for Bash. Existing
  sandbox auto-allow can bypass a whole-tool Bash ask rule; this probe records
  whether consent occurred and does not claim it always must occur.
- An owned Herdr server/client and real integrated local composer completed the
  harmless turn and exact Write Deny/Allow. The actual production parser accepted
  the replay; displayed original-card scope was checked before each decision.
  Deny left its target absent and Allow produced only the expected content.
  Public Claude capability remained absent. This is a local integration
  prerequisite, not a public `agent.prompt_exact` delivery claim.

The corresponding hook/MCP, Bash and integrated runs observed 15, 46 and 43
children respectively, with zero remaining living or zombie children, no harness
cleanup errors, and no supervisor survivors or emergency cleanup. Test-only
helper schedules also exercised actual buffered and partial writes across two
owned provider processes, delayed old-process exit, rejected old UI drafts and
a formerly valid old consent card that could not transfer to the replacement.

Pinned source confirms the print entry route, fixed explicit session, local-only
context-changing command types, Skill rejection of those command types, and
argument-gated background/preload entry points. The print mutation control
routes are absent from Herdr's typed writer allowlist. The final reachability
review remains open until every remaining adoption caller is reconciled.

The workflow adds independently pinned Claude native and shipped npm fallback
hook/MCP descriptor runs on both macOS and Linux, without model sampling or CI
authentication. Actual runs must pass before this workflow is platform evidence.
The shipped npm fallback also passed the actual macOS hook/MCP descriptor
probe, with three FDs in each receipt and no provider-input match. Both a fresh
native repeat and the fallback run observed 13 children and zero remaining
living or zombie children, with clean harness and supervisor reports. The
fallback launches the native executable once with inherited stdio and exits
with its status; normal npm installation instead hardlinks or copies the native
executable to its command path. Remaining acceptance includes completed source
reachability, actual Linux/macOS CI and separately enabled public exact delivery
with real smoke. Child-role diagnostics compare birth-verified executable identity
and command name only. They did not identify the earlier short-lived same-binary
child, whose role remains unproven; no full argv or environment was collected.
These owned-run observations do not resolve the separately tracked whole-suite
process-lifetime leaks.

## Final qualification evidence

[Run 35485588104](https://github.com/bfirestone/herdr/actions/runs/35485588104)
passed both jobs on that exact code revision with Rust 1.98.1:

- [Ubuntu job 106011233506](https://github.com/bfirestone/herdr/actions/runs/35485588104/job/106011233506):
  Ubuntu 24.04 x86_64; 3,882 Rust tests passed, six existing skips, all auxiliary
  and documentation gates passed. Both Codex 0.154.0 native/npm candidates passed
  null/private-pipe/PTY, hook and MCP descriptor checks, actual nonroot confinement,
  no-drift preview and exact profile/path/restriction/provider restoration.
- [macOS job 106011233636](https://github.com/bfirestone/herdr/actions/runs/35485588104/job/106011233636):
  macOS arm64; 3,660 Rust tests passed, six existing skips, all auxiliary and
  documentation gates and both Codex 0.154.0 native/npm descriptor checks passed.
  The repaired public API fixtures passed with the runner's normal TMPDIR.

The activation revision `6f9265028388205e2b63943c3d83799f20229280` passed root-run
native/npm live public-capability, fixed-thread, acknowledgment, harmless model
response, manual Allow/Deny and owned-cleanup checks on macOS arm64. The change
from that revision to `f84d5dd` affects only the API test fixture. The evaluator
independently verified that the production executable is byte-identical:
SHA-256 `3baaa7c72efcdc058414afb58d25e3a5bf72c8e067f106f551b092fa59f2081e`.
Those live results are reused exact-artifact evidence, not a claim that live
model calls were repeated at `f84d5dd`.

| Criterion | Source proof | Deterministic / public API proof | Live provider proof | Platform boundary |
| --- | --- | --- | --- | --- |
| Fixed recipient and acknowledgment | Pinned thread lookup, captured thread and admission response audit below | Fixed identity, exact Unicode/65,536-byte input, correlated acknowledgment and zero-write rejection | Both launchers: fixed thread, matching acknowledgment, harmless response | Live: macOS arm64; transport/API fixtures: both CI jobs |
| Capability and readiness projection | Owned launch and coherent fail-closed owner snapshot | Ping/list/get/snapshot, initialization/thread barriers, busy/consent transitions, invalid handshakes | Both launchers: public projection on actual launch and consent transitions | macOS/Linux source gate; only listed architectures exercised |
| Reset/replacement and queued input | Owner retirement and separate helper/control streams | Forced buffered/partial-write schedules, unknown outcome, stale-token exclusion and replacement isolation | Not forced by live smoke | Deterministic evidence in both platform suites |
| Child control-stream isolation | Shell/PTY/pipe, hook, MCP and npm-wrapper audit below | Harness safety and ownership tests | Shipped native/npm null/private-pipe/PTY, hook and MCP descriptor fixtures; no model sampling | macOS arm64 and confined disposable Ubuntu 24.04 x86_64 candidate |
| Explicit permission decisions | Correlated approval request and owner readiness | Approval correlation tests; evaluator consent check is supplementary | Both launchers: displayed matching cards, Deny prevents write, Allow produces expected content | macOS arm64, explicit disposable manual-review policy only |
| Owned lifetime and bootstrap | Owner revocation and helper teardown paths | Handshake failures, exit and fixture teardown; long-TMPDIR regression checks both sockets | Each live/descriptor candidate reports owned cleanup PASS | Candidate cleanup is proven; whole-suite lifetime/CPU limits remain below |

Code review is ADHERENT and specification review COMPLIANT. The evaluator's
retained acceptance contains 20 independent public API checks plus one
supplementary consent check; it independently revalidated the executable and
retained artifacts at `f84d5dd`, without rerunning those behavior checks. Consent
is supplementary because an earlier source read exposed approval-field details.
The retained setup failures and this independence limit were not erased. Root's
separate local gates passed 3,660 Rust tests (six existing skips), all auxiliary
checks and seven documentation tests.

The retained revision6 bundle includes `final-qualified-evidence.json`,
`actual-linux-f84d5dd-reports.json`, `actual-macos-f84d5dd-reports.json`, their
complete job logs, `root-live-reports.json` and the review/evaluation reports.
Per-mode `qualification: UNVERIFIED` remains in the raw harness reports:
descriptor mode does not establish model/manual consent, while live mode leaves
`child_fd_isolation` and `queued_reset_replacement` unverified. The combined
criterion-specific evidence above establishes this qualification; no single
mode is promoted to proof of every criterion. This documentation update does
not claim that actual CI ran on its later documentation-only commit.

## Qualification boundary and actual predecessor evidence

The earlier completed platform evidence remains the predecessor revision
`5609f4604d36af16eb4e41e360292e29759f9d0b`:

[Run 35481702996](https://github.com/bfirestone/herdr/actions/runs/35481702996)
passed on the exact predecessor above with Rust 1.98.1:

- [Ubuntu job 106000576264](https://github.com/bfirestone/herdr/actions/runs/35481702996/job/106000576264):
  Ubuntu 24.04 x86_64; 3,855 Rust tests, six existing skips, auxiliary and documentation gates passed.
  Both native/npm candidates passed null/private-pipe/PTY, hook and MCP descriptor
  isolation, safe placement and actual provider alias checks. The nonroot child
  reported stacked enforce mode, zero effective/permitted capabilities, NNP and
  seccomp; writes/network were denied with successful parent controls. Verify,
  no-drift preview, and exact profile/path/restriction/provider restoration passed.
  Original baseline RTM_NEWADDR/EPERM failures remain separately recorded.
- [macOS job 106000576046](https://github.com/bfirestone/herdr/actions/runs/35481702996/job/106000576046):
  macOS arm64; 3,633 Rust tests, six existing skips, auxiliary/docs gates and both native/npm
  descriptor checks passed. One HTTP handoff test was slow.

The source platform gate selects the macOS/Linux transport implementations.
Actual CI exercised only macOS arm64 and Ubuntu 24.04 x86_64. Linux descriptor
qualification uses the confined disposable runtime documented below, not an
arbitrary host's default policy. Other architectures, Linux graphical fidelity
and Linux live model/manual-consent behavior are not established by these runs.

These CI descriptor checks use empty provider homes and no account or model
sampling. The macOS model, fixed-thread acknowledgment and actual manual Allow/
Deny evidence is separately recorded below. Its stricter manual-review launcher
is a disposable-test exception, never production policy.

The predecessor Ubuntu runner's final cleanup killed four `herdr` and four `sh`
processes from unknown tests. The final `f84d5dd` run is the fourth observed Linux
run with that four-plus-four residue. No CPU, ancestry or provenance samples identify the cause.
Follow-up `herdr-0gdv.01btdj` tracks that suite-level lifetime gap. Individual
candidate cleanup PASS does not prove the entire suite had no surviving processes.
No corresponding runner termination lines were observed in the final macOS log;
that observation is not a whole-suite CPU or lifetime guarantee.

The intervening activation [run 35484221224](https://github.com/bfirestone/herdr/actions/runs/35484221224)
at `6f9265028388205e2b63943c3d83799f20229280` passed Linux (3,881 Rust tests,
six existing skips and native/npm descriptor/confinement/restoration checks),
but failed all three new macOS public API fixtures waiting for their sockets.
A 48-byte macOS-style TMPDIR produced a 106-byte API socket pathname. The bounded
reproduction found the socket library rejected it with `InvalidInput` and no
raw OS errno before binding. The repair uses an exclusively created private
compact fixture catalog, preserves lexical socket paths and canonical cwd, and
tests both API/client listeners under a long temporary root. No production
behavior, deadline, assertion or CI TMPDIR workaround changed. The first repair
run also exposed separate client-listener readiness; the fixture now waits for
that endpoint with the existing deadline. Both failures and their cleanup logs
remain retained; the final actual macOS job supplies the portability proof.

| Recipient / environment | Compatibility boundary |
| --- | --- |
| Owned integrated Codex 0.154.0, verified macOS/Linux transport | Qualified by the combined evidence above; actual architectures and Linux runtime policy are bounded as documented |
| Same owner during active turn, pending consent or unknown outcome | Identity retained, `ready: false`; admission refused |
| Starting/unbound, exited, reset, or revoked owner | No recipient capability; token cannot revive or rebind |
| Other Codex versions | Initialization fails closed |
| Claude Code 2.1.276 / SDK 0.3.276 | Local integrated launch implemented; no exact-prompt capability or desktop admission until its own real-provider proof |
| Windows or other platforms | No server capability |
| Shell-launched/detected or restored session without a live owner | No recipient capability, regardless of Codex/Claude-looking metadata |

The public offline acceptance drives an isolated server, helper, owner and real
provider pipes with a scripted provider. It checks ping/list/get/snapshot identity,
handshake barriers, zero prompt writes on rejection, exact 65,536-byte UTF-8
admission, correlated provider acceptance, busy/consent readiness, reset and
replacement. Owner tests cover unknown outcome, identity mismatch, unbound state
and admission-budget exhaustion. The opt-in live smoke now also verifies public
ping/list/get/snapshot fields against its actual launch and consent transitions.
Scripted acceptance and the completed live provider smoke supply separate proof.

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
  parsing. Cleanup failures remain sticky across repeated close calls and every
  intermediate provider instance; unverified cleanup retains scratch diagnostics.
  No user's process is terminated.

Process inspection is checked before launching a provider or creating scratch.
If inspection becomes unavailable later, the harness still closes and reaps its
directly owned processes, returns a redacted UNVERIFIED cleanup result, and keeps
diagnostic scratch. Live sessions retain previously observed descendants across
API calls so shutdown cannot forget an already observed, reparented child.

Local macOS results: native and normal npm wrapper passed null/private-pipe/PTY,
hook and MCP checks. Both recorded owned cleanup PASS and a matching stopped
hook without model output. The fixtures create an empty owned `CODEX_HOME`,
remove OpenAI authentication environment and Codex key/token variables, preserve
OS HOME, and require `account/read` to return no account. Both passed in this
unauthenticated configuration. The later actual predecessor and final CI results
above add Linux evidence; this early local run alone did not qualify Linux.

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
These pre-activation live results are retained. Root subsequently passed the
extended smoke for both launchers at activation revision `6f92650`, including
public ping/list/get/snapshot projection and consent readiness. Both runs used
the explicit disposable manual-review policy and reported owned cleanup PASS;
their supervisors recorded no rescue or unresolved owned process. The verified
byte-identical `f84d5dd` production artifact reuses these results alongside its
own completed actual platform CI, as recorded above. This does not establish
live model/manual-consent behavior on Linux or another architecture.

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
A workflow definition alone is not Linux or macOS run evidence. The final exact
code revision and actual job links above establish the completed platform gate.

Historical local validation before runtime and capability activation: `RUSTUP_TOOLCHAIN=1.98.1 just ci`
passed (3,511 nextest tests, six skipped, plus repository maintenance and asset
checks). `just docs-contract-test` passed all seven tests. Test fixture commits
used a process-only `commit.gpgsign=false` override; saved Git settings were
unchanged. An earlier restricted-host run failed process-observation and host-key
fixtures; the complete run with normal host access passed. No unrelated failure
was silently waived. That historical run did not supply actual macOS/Linux CI evidence; the
predecessor and final platform results above do. Final local/root gates and
independent review/evaluation are recorded separately from that historical run.

## Bounded Ubuntu runtime experiment history

The diagnostic baseline at `e6744b00428fe51be83b886317e794afc29f4984`,
[run 35417557753](https://github.com/bfirestone/herdr/actions/runs/35417557753),
passed the Rust gates on both platforms and native/npm descriptor fixtures on
macOS. All six Ubuntu original/supplemental commands failed before Python at
bubblewrap's loopback `RTM_NEWADDR` setup with `EPERM`; both launchers reaped
successfully. This identifies the failed operation, **not the selected executable
or specific denying LSM rule**. AppArmor was enabled and its unprivileged-userns
restriction was 1. Baseline LSM attribution remains unknown; no audit policy or
logging service is changed to manufacture evidence.

A separate CI experiment, initially unqualified, targets only the disposable Ubuntu 24.04
x86_64 job on `bfirestone/herdr`, branch `feat/desktop-exact-delivery`.
`scripts/ci_codex_sandbox.py` has explicit `plan`, `apply`, `verify`, `cleanup`,
`baseline`, and `candidate` modes. It refuses other OS/repository/ref/user targets.
The Linux baseline runs one fresh fixture per launcher with the existing two
supplemental diagnostic requests after null-control failure. Its exit and fixed
observations are recorded separately; an expected baseline failure is never
candidate success. macOS retains its original fixture path.

The candidate copies the already installed pinned package's exact bwrap bytes to
`/var/lib/herdr-codex-runtime/0.154.0/bwrap`. The expected resource size is 529,776
bytes and SHA-256 is
`01fb705f067bd5365b63d8ad2323a61c8d007733ca5e649437e086f3fb9935d8`.
This value was independently derived from the npm platform tarball after checking
registry SHA-512 integrity
`sha512-a4FI3A8sGtwGrOqltrPbrS2hajrHQG591EwmRfiRoLMb10VxdBtUGW4gu6IJVYENiYGA7k3P4jlRHEoCZU/s9Q==`.
That establishes registry-integrity provenance, not an independently verified
signing attestation. The installed package identity and original resource hash
are checked again at each setup/verification/cleanup boundary.

APT downloads only `apparmor-profiles=4.0.1really4.0.1-0ubuntu0.24.04.7`
using authenticated archive metadata. `dpkg-deb` reads its data archive; no package
installation or maintainer script runs. Only the shipped ABI-4
`bwrap-userns-restrict` member is read. Its SHA-256 must be
`11d39094f044f0cda0febb3ad517b830301da6b2ce929664af09ee9e4dd264f9`.
The sole byte substitution changes its executable attachment from `/usr/bin/bwrap`
to the fixed staged path. All permission rules, lowercase `px`/`pix` transitions,
child stacking and `audit deny capability` stay intact. Lowercase `px` does not
by itself establish environment sanitization. The distro bubblewrap package is
neither installed nor substituted.

The fixed staging path moved from `/opt` after run
[35420167666](https://github.com/bfirestone/herdr/actions/runs/35420167666)
refused unsafe ownership during read-only preflight, before apply. The hosted
Ubuntu image's setup makes `/opt` writable. The new `/var/lib` chain must pass
the same ownership checks on the actual runner; no preexisting directory is
chmodded or chowned to make setup succeed. This path correction alone does not
qualify Linux or exact Send.

Preflight checks existing ABI/include support, scalar restrictions, root-owned
nonwritable parent chains, absent owned files/profiles, and absent optional local
profile customizations. Failed runtime, profile and state parent-chain checks,
and provider-resource checks, emit distinct fixed `preflight_*` categories;
paths, ownership metadata and raw exception text are not emitted. Run
`35421006303` passed the new path checks, then refused `attachment_collision`
before apply. Its actual collision subtype remains unknown; neither failed
preflight loaded policy or staged the runtime.

The bounded private inventory reconciles hierarchical profile identities and modes
with the profile list: at most 4096 entries, depth 64 and 4096 UTF-8 bytes per
name/attachment. Nested owned-name collisions, malformed/unreadable metadata and
known or possible overlaps refuse. Exact kernel `attach` output `<unknown>` means
unavailable attachment text, not a proven conflict or disjointness. The pinned
parser serializes the attachment DFA without its literal string; the
[Linux AppArmor filesystem implementation](https://github.com/torvalds/linux/blob/v6.8/security/apparmor/apparmorfs.c#L1092)
returns that sentinel for this representation. Existing opaque entries are accepted
only under this disposable CI contract, with a fresh protected executable path and
mandatory real child selection proof. This does not establish global noninterference.
Read-only preflight emits only fixed inventory, overlap, owned-name, hash-support
and revision categories, plus a bounded profile count, before apply.

A fresh nonblocking descriptor reads the policy revision once, at most 32 bytes,
and closes; no EOF loop or polling is used. Strict decimal/newline validation and
equal revisions around each inventory are mandatory. `hash_policy` must already
be `Y`; it is never enabled by this experiment. Optional missing baseline profile
hashes remain unknown, but malformed present hashes refuse. Both new profiles
must expose valid kernel SHA256 hashes. These hash compiled policy payloads, not
the textual profile file. Existing restriction values remain unchanged.

The root-owned private journal is registered before runtime/policy mutation.
Only a no-load parse and add of the two absent profiles are supported, never
replacement or a service reload. The pinned parser loads the two top-level
profiles individually: ownership is confirmed only after the entire add succeeds,
the epoch advances by exactly two, baseline inventory is unchanged, and both
profiles are observed in enforce mode with valid hashes. `bwrap` may initially
report the exact staged literal or exact opaque sentinel; `unpriv_bwrap` must
report its plain name. The exact observed representations and hashes are durably
recorded and must remain equal. Failed/interrupted adds or uncertain observation
or journaling never acquire ownership of appearing names; the journal is retained
and cleanup refuses to unload them. An incomplete journal commit retains an
explicit marker that also blocks cleanup.

The candidate prepends the staged directory only to the fixture subprocess PATH.
The provider and all proof children remain the original nonroot runner user.
`--require-linux-enforcement` is accepted only for this Linux CI fixture target,
and cannot be combined with runtime diagnostics or live model/consent smoke.
One additional nonstreaming `command/exec` per launcher uses the unchanged cwd
and default policy, `timeoutMs=10000`, and the existing 30-second response budget.
There are no retries. Added controls have a 10-second help bound, at most three
one-second parent socket operations, a half-second child connection attempt,
and a 0.1-second listener check; the child attempt is inside the command budget.
Thus the added per-launcher proof is bounded by 43.1 seconds of explicit waits
plus local operations, within the unchanged 45-minute workflow limit. Existing
provider/descriptor/hook/MCP request and reap limits remain intact; the wrapper
does not kill the harness on a separate timeout that could strand its children.

Strict fixed booleans must prove Python startup, exact
`bwrap//&unpriv_bwrap (enforce)` child label, nonroot execution, zero effective and
permitted capabilities, no-new-privileges and seccomp filtering. PATH eligibility
alone is insufficient. The same child must fail to overwrite one fresh owned
canary outside all canonical cwd, CODEX_HOME, SQLite, `/tmp` and inherited
TMPDIR writable roots and fail to connect to an owned
parent loopback listener. Parent write/read and connection controls must succeed,
the canary must remain unchanged, and the listener must receive no child
connection. No user's existing file or external network endpoint is touched.
The original null/private-pipe/PTY, hook, MCP, no-account and cleanup assertions
remain mandatory. A missing, false or malformed enforcement field fails the
candidate. JSON diagnostics contain fixed categories/scalars, never raw provider
output, profile labels, PIDs, command arguments or arbitrary paths/environment.

The source3 experiment at `ec517bc0dcfcd34623aa82750e7d142f8ebf83d0`
(run `35422893035`, Linux attempt 2) passed preflight, confirmed the two owned
profile hashes and add epoch increment of two, and restored profiles, paths,
restrictions and provider bytes during cleanup. Its preflight classified 123
profiles as opaque-only. Both native and npm candidate fixtures failed with an
unclassified diagnostic and successful owned reap; the second no-drift preview
was skipped. This establishes setup and cleanup evidence, **not child selection,
enforcement, FD proof, or qualification**. The first Linux attempt stopped in
the unrelated federated reconnect test before the experiment; its failure is
retained separately and its cause remains unresolved.

Source4 adds failure observation only under `--require-linux-enforcement`.
`candidate_failure` reports a fixed current boundary (initialization; null,
pipe or PTY request/READY/write/response/descriptor checks; enforcement;
hook/MCP setup/requests/receipts; or cleanup) and per-mode booleans that become
true only after that mode's existing descriptor and input assertions pass.
A separate `candidate_cleanup_failure` preserves cleanup failure without losing
the original candidate failure, even where the existing top-level diagnostic
reports cleanup. These fields do not qualify the whole fixture.

The observer projects only the current owned command's already-received response:
a matching response consumed by the existing response method, or its matching
cached entry at failure. Client, active request and frame identity must match;
no request IDs are emitted. Presence, structural validity, bounded exit code,
output types/byte counts and the existing fixed runtime signatures are retained;
raw output/error text is not. An absent response is `not_observed`. A cached
terminal result during READY waiting may therefore accompany the original
deadline, without consuming that result or changing the wait. No new provider
request, read, retry, wait, timeout, policy or transport behavior is introduced.
The public wrapper also retains the literal initialization, account, provider,
bounds, input/isolation, enforcement, hook/MCP and cleanup failure categories;
unknown strings and invalid fields receive fixed fallbacks. Normal fixture
interaction and report behavior remains unchanged without the candidate flag.
The source4 run `35424421272` at
`758bb4b1d84b2c87ab238b1e0b6a2620df65be2c` passed native/npm null and pipe
checks, then failed at PTY READY waiting with a matching cached, structurally
valid RPC error. Its specific RPC code/message remains unknown. Owned provider
reap and root restoration passed; enforcement, hook/MCP and no-drift remain
unverified. The unchanged macOS job passed.

Source5 relocates only the Linux candidate's whole scratch to a fresh immediate
child of the explicitly inherited HOME, using the same per-launcher session
nonce. Baseline remains under `/tmp`; default and macOS fixtures are unchanged.
Pinned Codex source `6b9826e3aa83b1a5947db50f4332cb9c65f1b340` refuses release
helper aliases beneath Rust's temporary root, while PTY launch uses the alias
as its executable. This supports a placement repair hypothesis; it is not an
observed ENOENT or proof of the earlier RPC error's cause.

Before candidate provider invocation or scratch creation, metadata checks require
the exact nonroot Ubuntu target, explicit absolute canonical HOME, runner
ownership, and real root/runner-owned ancestors without group/other writes or
set-id modes. Ancestor `.git` markers (including files and symlinks) are rejected
without reading project or user configuration. Rust's temporary root is inherited
TMPDIR when present, otherwise `/tmp`; invalid, missing-on-disk, empty, relative
or symlink paths refuse instead of using Python's fallback rules. HOME and the
whole scratch must be outside that root and canonical `/tmp`. Existing HOME,
TMPDIR and parent permissions are never changed. The wrapper checks these
boundaries before registering candidate launches.

The harness rechecks retained parent identities at exclusive creation and after
owned providers/children are reaped, then requires the original runner-owned
0700 scratch identity before deletion. Replacement or metadata drift retains
the path and reports cleanup unverified. Candidate setup failures also enter
owned cleanup; candidate `owned_cleanup=PASS` is emitted only after deletion
succeeds. Only the created child is removed, including provider arg0 and SQLite
descendants. The separate denial canary remains a canonical HOME sibling outside
all writable roots. A bounded metadata-only observation after existing provider
initialization requires one provider-created `codex-linux-sandbox` symlink in
owned CODEX_HOME to resolve to the pinned package's native executable. Source6
requires real runner-owned codex-home/tmp/arg0 directories and a real runner-owned
session child, all without group/other writes or set-id modes. The arg0 ancestor
must be exactly 0700; safe 0700 or 0755 session children are accepted beneath it.
Pinned Codex explicitly makes arg0 private but does not promise a 0700 session
child. Earlier CI reported `candidate_scratch_changed` during initialization;
its actual child mode was not observed. Alias metadata failures now report
`candidate_alias_unverified`, while the task-owned scratch retains its exact
0700 and captured identity requirements. This observation creates no aliases
and makes no extra RPC, read, wait or retry. Public
`candidate_paths` contains only safe-parent, outside-temp and alias booleans.
The later predecessor run recorded above established actual Ubuntu parent
metadata, both native/npm aliases and PTY execution. Earlier source attempts
remain preserved as historical failures.

The final workflow step always attempts exact owned rollback after an attempted
apply. Before any candidate provider starts, a fresh fixed runner-owned status
record is created; it records each launcher's successful observed reap. An
incomplete/malformed status prevents root cleanup from removing policy underneath
an uncertain provider tree. Before any removal, root cleanup checks the original
restrictions and provider bytes, owned file identity/hash/ownership, unchanged
baseline inventory, confirmed owned modes/hashes/representations and recorded
epoch. Each single-profile removal must advance the epoch by exactly one and
remove exactly that profile. The remaining owned set and new epoch are durably
checkpointed before another removal. Unexpected revisions (including same-hash
replacement), representation/hash drift or an interrupted removal stop cleanup
and retain evidence. Original operation failure and cleanup failure remain
separate fixed categories, without raw exception text.

Cleanup then removes matching owned files and newly created parents, preserves
preexisting parents, and checks original restrictions/provider bytes/profile
inventory and path absence. Epoch restoration is not expected: confirmed owned
adds/removals naturally advance it. This is a conservative concurrency check,
not kernel compare-and-delete; it relies on an exclusive disposable CI policy
manager and does not protect against malicious concurrent root. Runner disposal
is extra containment, not evidence of verified cleanup. Before publication the
candidate commit can be reverted; the published diagnostic base remains the
configuration rollback.

Offline tests simulate Linux kernel/package-manager boundaries and exercise
hierarchical/opaque inventory, bounded nonblocking epoch reads, hash-policy and
owned-hash requirements, failed compound-add ownership refusal, epoch drift,
per-removal durable checkpoints, tamper, unknown ownership, redaction, child
observations and denial controls. They run through the existing Rust integration
gate. They are **not host-kernel or live CI enforcement evidence**. The predecessor
run above subsequently passed separate baseline/candidate recording, both complete
fixture checks, unchanged restrictions, no-drift preview and restored cleanup.
The final `f84d5dd` jobs repeated those runtime checks successfully. Combined with
the source audit, deterministic and independent public API evidence, and the
native/npm live smoke on the verified identical production artifact, they
complete Codex T3 qualification within the stated boundaries. Per-mode evidence
limits and the open suite-lifetime follow-up remain explicit. Claude and the
whole Desktop M2/SC0 milestone remain open.
