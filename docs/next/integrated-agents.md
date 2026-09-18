# Integrated Codex sessions (experimental)

An integrated session is an explicitly launched Herdr pane whose helper owns one
Codex app-server process and one fixed thread. Existing shell-launched agents
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

Server and per-agent exact-prompt capability fields remain absent in this slice.
The API and fixtures establish a candidate implementation, **not production
qualification**. Desktop Send must remain disabled until the separate pinned
provider proof passes, including real tool/hook/MCP descriptor inheritance,
permissions, conversation routing, and native macOS/Linux process lifecycle.
Windows fails closed because this bootstrap requires authenticated Unix PID/UID.

The bootstrap directory contains only a one-shot socket, is mode 0700, and is
removed after PID/UID plus nonce authentication. Prompt bodies travel through the
connected control stream and the owned provider stdin; never through the pane
PTY, argv, environment, or bootstrap files. This does not prevent the intended
provider, OS owner, or configured provider logging from seeing submitted text.
