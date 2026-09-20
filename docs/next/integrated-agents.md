# Integrated agent sessions (experimental)

An integrated session is an explicitly launched Herdr pane whose helper owns one
provider process and one fixed conversation: a Codex app-server thread or a
Claude Code session. Codex exact delivery is qualified for the pinned version;
Claude exact delivery remains unqualified until its separate proof gate.
Existing shell-launched agents
continue to use the existing terminal interaction and `agent.prompt` behavior.

```sh
herdr agent start --integrated codex --workspace WORKSPACE_ID --cwd TRUSTED_ABSOLUTE_PATH
```

Select an existing workspace and its canonical absolute directory (or a directory
inside it) that you trust. Launch creates a new tab and pane through direct argv;
it does not convert an existing agent or change installed binaries. The `codex`
on the server's PATH must implement the reviewed 0.154.0 protocol. Herdr preserves
provider authentication and configured approval/sandbox policy and displays the
effective policy returned by thread creation. Later versions require new proof.

The pane presents a text composer and sanitized provider output. Enter submits
ordinary text; provider slash commands, login, resume, fork and reset are not
supported. One submission or turn can be active across the composer and JSON API.
Ctrl+C explicitly closes this integrated session. Detaching a Herdr client leaves
the server-owned pane, helper and provider running.

Approval cards bind a provider request to its thread, turn and operation. Read the
complete details with PageUp/PageDown, then type `allow`, `deny`, or `cancel` and
press Enter. Allow applies once to a command/file operation, or only to the current
turn for a permission request. Persistent policy amendments are never offered.
Bounded non-secret tool questions accept comma-separated option numbers, one per
question. MCP forms support at most eight plain string or boolean fields; enter a
JSON object containing the displayed field names and your values. Authentication,
URL, local-only metadata and unknown form schemas are declined. Resolved cards become invalid immediately. Unsupported or incomplete
requests are denied; oversized control data ends the recipient. Ordinary output
may be truncated with a marker; approval details are never truncated to fit.

The experimental JSON method `agent.start_integrated` takes `provider`,
`workspace_id`, and `cwd`. Its result includes an agent and the new server/recipient
identities. `agent.prompt_exact` accepts `terminal_id`, `server_instance`,
`recipient_token`, and `text`, with the outer request ID used once. Text is limited
to 65,536 UTF-8 bytes, preserving embedded newlines and whitespace around content.
Empty, NUL-containing and slash-command text is rejected before provider writes.

An accepted `agent_prompt_exact_result` echoes those identities and includes
`acceptance: provider_input_accepted` and `submission_id`. Acceptance means a
correlated Codex turn-start response, not task completion. Pre-write rejections
use `unsupported_recipient`, `stale_recipient`, `not_ready`, `invalid_text`,
`queue_full`, or `revoked_before_write`. After any possible write, missing or
invalid acknowledgment is `outcome: unknown`; inspect before manually resending.
There is no reconnect, automatic retry or migration to a replacement process.

Codex 0.154.0 has qualified exact-prompt capabilities on supported macOS/Linux
owners; see [the recorded proof](integrated-agent-verification.md). Qualification
is specific to that provider and owned process. Claude remains unqualified: its
per-agent capability is absent and exact API submission returns
`unsupported_recipient`, including after local initialization and successful turns.
Desktop Send remains disabled for Claude until its separate real-provider proof
passes. Offline fixtures do not establish production qualification.
Windows fails closed because this bootstrap requires authenticated Unix PID/UID.

The bootstrap directory contains only a one-shot socket, is mode 0700, and is
removed after PID/UID plus nonce authentication. Prompt bodies travel through the
connected control stream and the owned provider stdin; never through the pane
PTY, argv, environment, or bootstrap files. This does not prevent the intended
provider, OS owner, or configured provider logging from seeing submitted text.

## Claude Code local integration (unqualified)

```sh
herdr agent start --integrated claude --workspace WORKSPACE_ID --cwd TRUSTED_ABSOLUTE_PATH
```

This explicitly trusts the selected working directory: Claude print mode does not
present the interactive workspace trust prompt. The server launches `claude` from
PATH using stream-JSON input/output, verbose output, replayed user messages, a
fresh session UUID and stdio permission prompts. A matched initialize exchange
and `get_binary_version` response must establish CLI 2.1.276 (SDK protocol
0.3.276) before the composer admits its first prompt. No existing conversation is
resumed or forked. Authentication and configured tool policy remain in effect;
launch-local exclusions disable `EnterPlanMode` and `ExitPlanMode`, including
when configured policy would otherwise allow them. No saved policy is changed.

The initialized session initially awaits confirmation. Exactly one local bootstrap
prompt may enter that state. Acceptance requires a same-stream replay containing
its exact UUID, session ID, user role and text, `isReplay: true`, and a null parent
tool-use ID. A result event means completion, never input acceptance. Further
prompts require the completed turn to leave the session idle. A reset, invalid
replay, disconnected stream or protocol overflow retires the recipient; uncertain
input is never retried or passed to another process.

Claude consent cards show the complete bounded original input for supported
Bash, Read, Write, Edit, Glob and Grep operations. Typing `allow` returns that input
unchanged once; `deny` or `cancel` returns a denial. No persistent permission grants
are sent. AskUserQuestion displays the actual questions/options and requires
answers: enter comma-separated option numbers, or a JSON object mapping each
complete question to an answer string (including free text or multiple choices).
A generic `allow` cannot answer a question.

MCP tools, subagent approvals, plan transitions, unknown tool schemas and local-only
consent disclosures are unsupported and denied. Unknown dialog kinds retire the
session without claiming the user dismissed them. Oversized consent never gets a
truncated Allow option. Existing provider policy or hooks may permit supported
tools without asking Herdr; this is not a promise that every tool requires a click.

Claude replay/routing, real approvals and descriptor inheritance still require the
separate pinned-provider macOS/Linux proof. Do not treat this implementation or its
fake-provider tests as qualification for desktop Send.
