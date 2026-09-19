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

## Bounded Ubuntu runtime experiment (not qualification)

The diagnostic baseline at `e6744b00428fe51be83b886317e794afc29f4984`,
[run 35417557753](https://github.com/bfirestone/herdr/actions/runs/35417557753),
passed the Rust gates on both platforms and native/npm descriptor fixtures on
macOS. All six Ubuntu original/supplemental commands failed before Python at
bubblewrap's loopback `RTM_NEWADDR` setup with `EPERM`; both launchers reaped
successfully. This identifies the failed operation, **not the selected executable
or specific denying LSM rule**. AppArmor was enabled and its unprivileged-userns
restriction was 1. Baseline LSM attribution remains unknown; no audit policy or
logging service is changed to manufacture evidence.

A separate, unqualified CI experiment targets only the disposable Ubuntu 24.04
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
canary outside cwd and `/tmp` writable roots and fail to connect to an owned
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
Actual failure phase and cause remain unknown until the new exact-commit run;
these local observations do not identify an AppArmor or PTY defect.

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
gate. They are **not host-kernel or live CI enforcement evidence**. This candidate
still needs one independently reviewed, published exact-commit branch run showing
separate baseline/candidate results, both complete fixture passes, unchanged
restrictions, second preview with no drift and restored cleanup. No Linux
qualification, Desktop M2/T3 closure, or exact Send activation follows from these
local tests or the workflow definition.
