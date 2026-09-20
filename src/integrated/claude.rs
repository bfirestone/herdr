//! Claude Code 2.1.276 / Agent SDK 0.3.276, one fresh fixed session per process.
use super::{
    approvals::Card,
    codex::{Effect, SubmissionOrigin},
    identity::valid_text,
    owner::{OwnerState, SubmissionOutcome},
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

const VERSION: &str = "2.1.276";
struct Pending {
    uuid: String,
    text: String,
    origin: SubmissionOrigin,
}
pub(super) struct Claude {
    session: String,
    cwd: String,
    stage: u8,
    confirmed: bool,
    pending: Option<Pending>,
    cards: BTreeMap<String, Card>,
    seen_controls: HashSet<String>,
    // At most 16 cards plus settlements, each settlement at most 64 KiB (1 MiB total).
    settlements: BTreeMap<String, Value>,
    pub state: OwnerState,
}

pub(super) fn fresh_uuid() -> std::io::Result<String> {
    let nonce = crate::platform::recipient_random()?;
    // RFC 4122 version 4, generated from the same OS entropy as owner identities.
    Ok(format!(
        "{}-{}-4{}-a{}-{}",
        &nonce[..8],
        &nonce[8..12],
        &nonce[13..16],
        &nonce[17..20],
        &nonce[20..32]
    ))
}
impl Claude {
    pub fn new(cwd: String, session: String) -> Self {
        Self {
            cwd,
            session,
            stage: 0,
            confirmed: false,
            pending: None,
            cards: BTreeMap::new(),
            seen_controls: HashSet::new(),
            settlements: BTreeMap::new(),
            state: OwnerState::Starting,
        }
    }
    pub fn initialize() -> Value {
        json!({"type":"control_request","request_id":"initialize","request":{"subtype":"initialize"}})
    }
    pub fn command(session: &str) -> std::process::Command {
        let mut command = std::process::Command::new("claude");
        command.args([
            "--print",
            "--input-format",
            "stream-json",
            "--output-format",
            "stream-json",
            "--verbose",
            "--replay-user-messages",
            "--session-id",
            session,
            "--permission-prompt-tool",
            "stdio",
            "--disallowedTools",
            "EnterPlanMode,ExitPlanMode",
        ]);
        command
    }
    pub fn cards(&self) -> Vec<Card> {
        self.cards.values().cloned().collect()
    }
    pub fn submit(&mut self, origin: SubmissionOrigin, text: String) -> Vec<Effect> {
        // Pinned CLI Yw/yM parse commands after JavaScript trim(), which also
        // removes U+FEFF. Rust whitespace alone would admit BOM-prefixed /clear.
        // Preserve valid text byte-for-byte; this is admission, not normalization.
        let reject = if !valid_text(&text)
            || text
                .trim_start_matches(|c: char| c.is_whitespace() || c == '\u{feff}')
                .starts_with('/')
        {
            Some("invalid_text")
        } else if matches!(origin, SubmissionOrigin::Remote(_)) {
            Some("unsupported_recipient")
        } else if self.pending.is_some() {
            Some("queue_full")
        } else if !matches!(
            self.state,
            OwnerState::Idle | OwnerState::AwaitingSessionConfirmation
        ) {
            Some("not_ready")
        } else {
            None
        };
        if let Some(code) = reject {
            return vec![
                Effect::Result(origin, SubmissionOutcome::rejected(code)),
                Effect::State(self.state),
            ];
        }
        let Ok(uuid) = fresh_uuid() else {
            self.state = OwnerState::Revoked;
            return vec![
                Effect::Result(origin, SubmissionOutcome::rejected("revoked_before_write")),
                Effect::State(self.state),
            ];
        };
        let frame = json!({"type":"user","uuid":uuid,"session_id":self.session,"parent_tool_use_id":null,"message":{"role":"user","content":text}});
        self.pending = Some(Pending { uuid, text, origin });
        self.state = OwnerState::ActiveTurn;
        vec![Effect::State(self.state), Effect::Write(frame)]
    }
    pub fn event(&mut self, frame: Value) -> Result<Vec<Effect>, ()> {
        if self.state == OwnerState::Revoked {
            return Err(());
        }
        if let Some(session) = frame.get("session_id") {
            if session != &self.session {
                return Err(());
            }
        }
        match frame["type"].as_str().ok_or(())? {
            "control_response" => {
                let response = &frame["response"];
                if self.stage == 2 {
                    let id = control_id(response)?;
                    if self.settlements.get(id) != Some(&frame) {
                        return Err(());
                    }
                    self.settlements.remove(id);
                    return Ok(vec![]);
                }
                if response["subtype"] != "success" {
                    return Err(());
                }
                if self.stage == 0 && response["request_id"] == "initialize" {
                    let body = &response["response"];
                    if !body["commands"].is_array()
                        || !body["models"].is_array()
                        || !body["agents"].is_array()
                        || !body["output_style"].is_string()
                        || response["pending_permission_requests"] != json!([])
                        || response["pending_user_dialog_requests"] != json!([])
                    {
                        return Err(());
                    }
                    self.stage = 1;
                    return Ok(vec![Effect::Write(
                        json!({"type":"control_request","request_id":"version","request":{"subtype":"get_binary_version"}}),
                    )]);
                }
                if self.stage == 1
                    && response["request_id"] == "version"
                    && response["response"]["version"] == VERSION
                {
                    self.stage = 2;
                    self.state = OwnerState::AwaitingSessionConfirmation;
                    return Ok(vec![Effect::State(self.state), Effect::Text("Claude initialized. One local prompt may confirm this fresh session; desktop Send is unqualified.\n".into())]);
                }
                Err(())
            }
            "control_request" => self.control(frame),
            "control_cancel_request" => {
                let id = control_id(&frame)?;
                self.cards.remove(id);
                if self.state == OwnerState::PendingPermission && self.cards.is_empty() {
                    self.state = OwnerState::ActiveTurn;
                    return Ok(vec![Effect::State(self.state)]);
                }
                Ok(vec![])
            }
            "keep_alive" => Ok(vec![]),
            "conversation_reset" => Err(()),
            "user" if frame["isReplay"] != true => {
                self.ordinary_context(&frame, true)?;
                if frame.get("parent_tool_use_id") != Some(&Value::Null)
                    || frame.get("isReplay").is_some_and(|v| v != false)
                    || frame["message"]["role"] != "user"
                    || self
                        .pending
                        .as_ref()
                        .is_some_and(|p| frame["uuid"] == p.uuid)
                    || !frame["message"]["content"]
                        .as_array()
                        .is_some_and(|blocks| {
                            !blocks.is_empty()
                                && blocks.iter().all(|b| {
                                    b["type"] == "tool_result"
                                        && bounded_id(&b["tool_use_id"])
                                        && b.get("is_error").is_none_or(Value::is_boolean)
                                        && b.get("content")
                                            .is_none_or(|v| v.is_string() || v.is_array())
                                })
                        })
                {
                    return Err(());
                }
                // Ordinary tool output is never an input acknowledgment.
                Ok(vec![])
            }
            "user" => {
                let pending = self.pending.as_ref().ok_or(())?;
                if self.stage != 2
                    || frame["session_id"] != self.session
                    || frame["uuid"] != pending.uuid
                    || frame["isReplay"] != true
                    || frame.get("parent_tool_use_id") != Some(&Value::Null)
                    || frame["message"]["role"] != "user"
                    || frame["message"]["content"] != pending.text
                    || frame["isSynthetic"] == true
                {
                    return Err(());
                }
                let pending = self.pending.take().ok_or(())?;
                self.confirmed = true;
                Ok(vec![Effect::Result(
                    pending.origin,
                    SubmissionOutcome::Accepted {
                        submission_id: pending.uuid,
                    },
                )])
            }
            "result" => {
                // A result cannot substitute for the input replay, even on success.
                if frame["session_id"] != self.session
                    || !matches!(
                        frame["subtype"].as_str(),
                        Some(
                            "success"
                                | "error_during_execution"
                                | "error_max_turns"
                                | "error_max_budget_usd"
                                | "error_max_structured_output_retries"
                        )
                    )
                    || !self.confirmed
                    || self.pending.is_some()
                    || !matches!(
                        self.state,
                        OwnerState::ActiveTurn | OwnerState::PendingPermission
                    )
                {
                    return Err(());
                }
                self.cards.clear();
                // Error settlements need not echo. Never carry stale responses into a new turn.
                self.settlements.clear();
                self.state = OwnerState::Idle;
                Ok(vec![
                    Effect::State(self.state),
                    Effect::Text("\n[turn completed]\n".into()),
                ])
            }
            "system" => {
                if matches!(
                    frame["subtype"].as_str(),
                    Some("hook_started" | "hook_progress" | "hook_response")
                ) {
                    // SDK 0.3.276 / pinned CLI emit SessionStart and Setup hook
                    // lifecycle before the initialize reply. These bounded frames
                    // neither confirm a session nor change admission/consent state.
                    if frame["session_id"] != self.session
                        || !bounded_id(&frame["uuid"])
                        || frame
                            .get("parent_tool_use_id")
                            .is_some_and(|v| !v.is_null())
                        || frame.get("subagent_type").is_some()
                        || frame.get("agent_id").is_some()
                        || !startup_hook(&frame)
                    {
                        return Err(());
                    }
                    return Ok(vec![]);
                }
                self.ordinary_context(&frame, false)?;
                if frame["subtype"] == "init" {
                    if self.stage != 2
                        || frame["claude_code_version"] != VERSION
                        || frame["cwd"] != self.cwd
                        || !frame["permissionMode"].is_string()
                    {
                        return Err(());
                    }
                    return Ok(vec![Effect::Text(format!(
                        "Claude configured permission mode: {}\n",
                        frame["permissionMode"]
                    ))]);
                }
                if !ordinary_system(&frame) {
                    return Err(());
                }
                Ok(vec![])
            }
            "command_lifecycle" => {
                self.ordinary_context(&frame, false)?;
                if !bounded_id(&frame["command_uuid"])
                    || !matches!(
                        frame["state"].as_str(),
                        Some(
                            "queued"
                                | "started"
                                | "completed"
                                | "cancelled"
                                | "discarded"
                                | "refused"
                        )
                    )
                {
                    return Err(());
                }
                // The pinned CLI emits queue/command notifications independently
                // of input replay and tool consent. They acknowledge neither.
                Ok(vec![])
            }
            "rate_limit_event" | "tool_progress" | "tool_use_summary" => {
                self.ordinary_context(&frame, frame["type"] != "rate_limit_event")?;
                if !ordinary_information(&frame) {
                    return Err(());
                }
                Ok(vec![])
            }
            "assistant" => {
                if frame["session_id"] != self.session || self.stage != 2 {
                    return Err(());
                }
                let content = frame["message"]["content"].as_array().ok_or(())?;
                Ok(content
                    .iter()
                    .filter_map(|block| {
                        (block["type"] == "text")
                            .then(|| block["text"].as_str())
                            .flatten()
                            .map(|text| Effect::Text(text.into()))
                    })
                    .collect())
            }
            // This adapter does not request partial messages; never infer identity from them.
            _ => Err(()),
        }
    }
    fn ordinary_context(&self, frame: &Value, active: bool) -> Result<(), ()> {
        if self.stage != 2
            || frame["session_id"] != self.session
            || !bounded_id(&frame["uuid"])
            || frame
                .get("parent_tool_use_id")
                .is_some_and(|v| !v.is_null())
            || frame.get("subagent_type").is_some()
            || frame.get("agent_id").is_some()
            || (active
                && !matches!(
                    self.state,
                    OwnerState::ActiveTurn | OwnerState::PendingPermission
                ))
        {
            return Err(());
        }
        Ok(())
    }
    fn settlement(&mut self, id: &str, frame: Value) -> Result<Effect, ()> {
        // The pinned input reader echoes successful settlements with replay enabled;
        // errors can be consumed without an echo. Both are optional, exact, one-use.
        if self.settlements.len() + self.cards.len() >= 16
            || serde_json::to_vec(&frame).map_err(|_| ())?.len() > 64 * 1024
            || self.settlements.contains_key(id)
        {
            return Err(());
        }
        self.settlements.insert(id.into(), frame.clone());
        Ok(Effect::Write(frame))
    }
    fn control(&mut self, frame: Value) -> Result<Vec<Effect>, ()> {
        let id = control_id(&frame)?.to_owned();
        if self.stage != 2
            || !matches!(
                self.state,
                OwnerState::ActiveTurn | OwnerState::PendingPermission
            )
            || self.cards.len() + self.settlements.len() >= 16
            || self.seen_controls.len() >= 4096
            || !self.seen_controls.insert(id.clone())
        {
            return Err(());
        }
        let request = &frame["request"];
        if request["subtype"] == "request_user_dialog" {
            // SDK 0.3.276 forbids answering a dialog kind we did not declare.
            return Err(());
        }
        if request["subtype"] != "can_use_tool" {
            return Ok(vec![
                Effect::Text("Unsupported Claude control denied.\n".into()),
                self.settlement(&id,
                    json!({"type":"control_response","response":{"subtype":"error","request_id":id,"error":"Unsupported integrated interaction"}}),
                )?,
            ]);
        }
        let supported = supported_request(request);
        if !supported {
            return Ok(vec![
                Effect::Text("Unsupported or incomplete Claude operation denied.\n".into()),
                self.settlement(
                    &id,
                    permission_response(
                        &id,
                        json!({"behavior":"deny","message":"Unsupported integrated interaction"}),
                    ),
                )?,
            ]);
        }
        let mut details = serde_json::to_string_pretty(request).map_err(|_| ())?;
        if request["tool_name"] == "AskUserQuestion" {
            details.push_str("\nAnswer with a JSON object mapping each complete question to your answer, or comma-separated option numbers (one per question). Type deny or cancel to decline. Generic allow is unavailable.");
        }
        if super::render::sanitize(&details).len() > 16 * 1024 {
            return Ok(vec![
                Effect::Text("Claude consent exceeds the display bound; denied.\n".into()),
                self.settlement(&id, permission_response(
                    &id,
                    json!({"behavior":"deny","message":"Consent details exceed integrated display limit"}),
                ))?,
            ]);
        }
        self.cards.insert(
            id.clone(),
            Card {
                id: json!(id),
                method: format!("Claude {}", request["tool_name"].as_str().ok_or(())?),
                params: request.clone(),
                details,
            },
        );
        self.state = OwnerState::PendingPermission;
        Ok(vec![Effect::State(self.state)])
    }
    pub fn decision(&mut self, id: &Value, decision: &str) -> Vec<Effect> {
        if self.state == OwnerState::Revoked {
            return vec![];
        }
        let Some(id) = id.as_str() else {
            return vec![];
        };
        let Some(card) = self.cards.get(id) else {
            return vec![];
        };
        let request = &card.params;
        let result = match decision {
            "deny" | "cancel" => {
                json!({"behavior":"deny","message":"User declined integrated operation"})
            }
            "allow" if request["tool_name"] != "AskUserQuestion" => {
                json!({"behavior":"allow","updatedInput":request["input"]})
            }
            _ if request["tool_name"] == "AskUserQuestion" => {
                let Some(answers) = answers(&request["input"], decision) else {
                    return vec![];
                };
                let mut input = request["input"].clone();
                input["answers"] = answers;
                json!({"behavior":"allow","updatedInput":input})
            }
            _ => return vec![],
        };
        self.cards.remove(id);
        self.state = if self.cards.is_empty() {
            OwnerState::ActiveTurn
        } else {
            OwnerState::PendingPermission
        };
        match self.settlement(id, permission_response(id, result)) {
            Ok(write) => vec![write, Effect::State(self.state)],
            Err(()) => {
                self.cards.clear();
                self.settlements.clear();
                self.state = OwnerState::Revoked;
                vec![Effect::State(self.state)]
            }
        }
    }
}
fn bounded_id(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|s| !s.is_empty() && s.len() <= 256)
}
fn nonnegative(value: &Value) -> bool {
    value.as_f64().is_some_and(|n| n.is_finite() && n >= 0.0)
}
fn optional_fields(value: &Value, keys: &[&str], valid: fn(&Value) -> bool) -> bool {
    keys.iter().all(|key| value.get(*key).is_none_or(valid))
}
fn ordinary_information(frame: &Value) -> bool {
    // SDK 0.3.276 and the pinned print encoder emit these without partial output.
    match frame["type"].as_str() {
        Some("rate_limit_event") => {
            let info = &frame["rate_limit_info"];
            info.is_object()
                && matches!(
                    info["status"].as_str(),
                    Some("allowed" | "allowed_warning" | "rejected")
                )
                && optional_fields(
                    info,
                    &[
                        "resetsAt",
                        "utilization",
                        "overageResetsAt",
                        "surpassedThreshold",
                    ],
                    nonnegative,
                )
                && optional_fields(
                    info,
                    &[
                        "rateLimitType",
                        "overageStatus",
                        "overageDisabledReason",
                        "limitScope",
                        "errorCode",
                    ],
                    Value::is_string,
                )
                && optional_fields(
                    info,
                    &[
                        "isUsingOverage",
                        "overageInUse",
                        "canUserPurchaseCredits",
                        "hasChargeableSavedPaymentMethod",
                    ],
                    Value::is_boolean,
                )
        }
        Some("tool_progress") => {
            bounded_id(&frame["tool_use_id"])
                && bounded_id(&frame["tool_name"])
                && frame.get("parent_tool_use_id") == Some(&Value::Null)
                && nonnegative(&frame["elapsed_time_seconds"])
                && optional_fields(frame, &["heartbeat"], Value::is_boolean)
                && optional_fields(frame, &["task_id"], bounded_id)
                && frame.get("subagent_retry").is_none()
        }
        Some("tool_use_summary") => {
            frame["summary"].is_string()
                && frame["preceding_tool_use_ids"]
                    .as_array()
                    .is_some_and(|ids| ids.iter().all(bounded_id))
        }
        _ => false,
    }
}
fn ordinary_system(frame: &Value) -> bool {
    // An explicit informational allowlist replaces blanket system-message ignoring.
    // Reset, compaction boundaries, fallback rewinds and untested local-consent
    // transitions remain fail-closed; none of these messages acknowledges input.
    match frame["subtype"].as_str() {
        Some("status") => {
            frame.get("status").is_some_and(|v| {
                v.is_null() || matches!(v.as_str(), Some("compacting" | "requesting"))
            }) && optional_fields(
                frame,
                &["permissionMode", "compact_result", "compact_error"],
                Value::is_string,
            )
        }
        Some("notification") => {
            bounded_id(&frame["key"])
                && frame["text"].is_string()
                && matches!(
                    frame["priority"].as_str(),
                    Some("low" | "medium" | "high" | "immediate")
                )
                && optional_fields(frame, &["color"], Value::is_string)
                && optional_fields(frame, &["timeout_ms"], nonnegative)
        }
        Some("api_retry") => {
            ["attempt", "max_retries", "retry_delay_ms"]
                .iter()
                .all(|k| nonnegative(&frame[*k]))
                && frame
                    .get("error_status")
                    .is_some_and(|v| v.is_null() || nonnegative(v))
                && frame["error"].is_string()
                && frame.get("no_response").is_none_or(|v| {
                    nonnegative(&v["waited_ms"]) && nonnegative(&v["retry_wait_ms"])
                })
        }
        Some("thinking_tokens") => {
            nonnegative(&frame["estimated_tokens"])
                && nonnegative(&frame["estimated_tokens_delta"])
                && optional_fields(frame, &["user_message_uuid"], bounded_id)
        }
        Some("memory_recall") => {
            matches!(frame["mode"].as_str(), Some("select" | "synthesize"))
                && frame["memories"].as_array().is_some_and(|memories| {
                    memories.iter().all(|m| {
                        m["path"].is_string()
                            && matches!(
                                m["scope"].as_str(),
                                Some("personal" | "team" | "organization")
                            )
                            && optional_fields(m, &["content"], Value::is_string)
                    })
                })
        }
        Some("model_fallback") => ["trigger", "original_model", "fallback_model", "content"]
            .iter()
            .all(|k| frame[*k].is_string()),
        Some("model_refusal_no_fallback") => {
            frame["original_model"].is_string()
                && frame["content"].is_string()
                && frame
                    .get("request_id")
                    .is_some_and(|v| v.is_null() || bounded_id(v))
                && optional_fields(
                    frame,
                    &[
                        "api_refusal_category",
                        "api_refusal_explanation",
                        "refused_user_message_uuid",
                    ],
                    |v| v.is_null() || v.is_string(),
                )
        }
        _ => false,
    }
}
fn startup_hook(frame: &Value) -> bool {
    if !bounded_id(&frame["hook_id"])
        || !frame["hook_name"].is_string()
        || !matches!(frame["hook_event"].as_str(), Some("SessionStart" | "Setup"))
    {
        return false;
    }
    match frame["subtype"].as_str() {
        Some("hook_started") => true,
        Some("hook_progress" | "hook_response") => {
            ["stdout", "stderr", "output"]
                .iter()
                .all(|key| frame[*key].is_string())
                && (frame["subtype"] == "hook_progress"
                    || (matches!(
                        frame["outcome"].as_str(),
                        Some("success" | "error" | "cancelled")
                    ) && frame.get("exit_code").is_none_or(Value::is_i64)))
        }
        _ => false,
    }
}
fn control_id(frame: &Value) -> Result<&str, ()> {
    frame["request_id"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 256)
        .ok_or(())
}
fn permission_response(id: &str, result: Value) -> Value {
    json!({"type":"control_response","response":{"subtype":"success","request_id":id,"response":result}})
}
fn supported_request(request: &Value) -> bool {
    let Some(fields) = request.as_object() else {
        return false;
    };
    if fields.keys().any(|key| {
        ![
            "subtype",
            "tool_name",
            "input",
            "permission_suggestions",
            "blocked_path",
            "decision_reason",
            "decision_reason_type",
            "classifier_approvable",
            "suppress_always_allow_rule",
            "default_to_no",
            "matched_ask_rule",
            "title",
            "display_name",
            "tool_use_id",
            "description",
            "requires_user_interaction",
        ]
        .contains(&key.as_str())
    }) || request["tool_use_id"].as_str().is_none_or(str::is_empty)
        || !request["input"].is_object()
        || [
            "requires_user_interaction",
            "default_to_no",
            "suppress_always_allow_rule",
            "classifier_approvable",
        ]
        .iter()
        .any(|key| request.get(*key).is_some_and(|v| !v.is_boolean()))
    {
        return false;
    }
    // MCP, subagents, plan transitions and local-only disclosure flows are unqualified.
    match request["tool_name"].as_str() {
        Some("AskUserQuestion") => valid_questions(&request["input"]),
        Some("Bash" | "Read" | "Write" | "Edit" | "Glob" | "Grep") => {
            request["requires_user_interaction"] != true
        }
        _ => false,
    }
}
fn valid_questions(input: &Value) -> bool {
    let Some(fields) = input.as_object() else {
        return false;
    };
    if fields.keys().any(|k| k != "questions") {
        return false;
    }
    let Some(questions) = input["questions"].as_array() else {
        return false;
    };
    let mut seen = HashSet::new();
    (1..=4).contains(&questions.len())
        && questions.iter().all(|q| {
            q.as_object().is_some_and(|o| {
                o.keys()
                    .all(|k| ["question", "header", "options", "multiSelect"].contains(&k.as_str()))
            }) && q["question"]
                .as_str()
                .is_some_and(|s| !s.is_empty() && seen.insert(s))
                && q["header"].is_string()
                && q["multiSelect"].is_boolean()
                && q["options"].as_array().is_some_and(|options| {
                    (2..=4).contains(&options.len())
                        && options.iter().all(|o| {
                            o.as_object().is_some_and(|fields| {
                                fields.keys().all(|k| {
                                    ["label", "description", "preview"].contains(&k.as_str())
                                })
                            }) && o["label"].as_str().is_some_and(|s| !s.is_empty())
                                && o["description"].is_string()
                                && (o["preview"].is_null() || o["preview"].is_string())
                        })
                })
        })
}
fn answers(input: &Value, decision: &str) -> Option<Value> {
    let questions = input["questions"].as_array()?;
    let answer: Value = serde_json::from_str(decision)
        .ok()
        .filter(Value::is_object)
        .or_else(|| {
            let indices: Vec<usize> = decision
                .split(',')
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?;
            if indices.len() != questions.len() {
                return None;
            }
            let mut values = serde_json::Map::new();
            for (question, index) in questions.iter().zip(indices) {
                let label = question["options"].as_array()?.get(index.checked_sub(1)?)?["label"]
                    .as_str()?;
                values.insert(question["question"].as_str()?.into(), json!(label));
            }
            Some(Value::Object(values))
        })?;
    let values = answer.as_object()?;
    if values.len() != questions.len()
        || questions.iter().any(|q| {
            q["question"]
                .as_str()
                .and_then(|question| values.get(question))
                .and_then(Value::as_str)
                .is_none_or(|s| s.trim().is_empty() || s.len() > 1024)
        })
    {
        return None;
    }
    Some(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn initialized() -> Claude {
        let mut p = Claude::new("/tmp/trusted".into(), "fixed-session".into());
        let effects = p.event(json!({"type":"control_response","response":{"subtype":"success","request_id":"initialize","pending_permission_requests":[],"pending_user_dialog_requests":[],"response":{"commands":[],"agents":[],"models":[],"output_style":"default"}}})).unwrap();
        assert!(
            matches!(&effects[0], Effect::Write(v) if v["request"]["subtype"] == "get_binary_version")
        );
        p.event(json!({"type":"control_response","response":{"subtype":"success","request_id":"version","response":{"version":VERSION}}})).unwrap();
        assert_eq!(p.state, OwnerState::AwaitingSessionConfirmation);
        p
    }
    fn submitted(p: &mut Claude) -> Value {
        let effects = p.submit(SubmissionOrigin::Local(1), "  exact\ntext ' \"  ".into());
        effects
            .into_iter()
            .find_map(|e| match e {
                Effect::Write(v) => Some(v),
                _ => None,
            })
            .unwrap()
    }
    fn replay(mut message: Value) -> Value {
        message["isReplay"] = json!(true);
        message
    }
    fn request(id: &str, tool: &str, input: Value) -> Value {
        json!({"type":"control_request","request_id":id,"request":{"subtype":"can_use_tool","tool_name":tool,"tool_use_id":format!("tool-{id}"),"input":input}})
    }
    fn write(effects: Vec<Effect>) -> Value {
        effects
            .into_iter()
            .find_map(|e| match e {
                Effect::Write(v) => Some(v),
                _ => None,
            })
            .unwrap()
    }
    #[test]
    fn command_lifecycle_never_substitutes_for_replay_or_changes_admission() {
        for state in [
            "queued",
            "started",
            "completed",
            "cancelled",
            "discarded",
            "refused",
        ] {
            let mut p = initialized();
            let submitted = submitted(&mut p);
            let frame = json!({"type":"command_lifecycle","session_id":"fixed-session",
                "uuid":"event","command_uuid":submitted["uuid"],"state":state});
            assert!(p.event(frame.clone()).unwrap().is_empty());
            assert!(!p.confirmed);
            assert!(p.pending.is_some());
            assert_eq!(p.state, OwnerState::ActiveTurn);
            p.event(replay(submitted)).unwrap();
            p.event(request("consent", "Bash", json!({"command":"printf safe"})))
                .unwrap();
            assert!(p.event(frame.clone()).unwrap().is_empty());
            assert_eq!(p.state, OwnerState::PendingPermission);
            assert_eq!(p.cards.len(), 1);
            for (key, value) in [
                ("session_id", json!("replacement")),
                ("uuid", Value::Null),
                ("command_uuid", Value::Null),
                ("state", json!("reset")),
                ("parent_tool_use_id", json!("child")),
            ] {
                let mut invalid = frame.clone();
                invalid[key] = value;
                assert!(p.event(invalid).is_err());
            }
            p.state = OwnerState::Revoked;
            assert!(p.event(frame).is_err());
        }
    }
    #[test]
    fn startup_hook_lifecycle_is_informational_before_initialize_and_during_turn() {
        for subtype in ["hook_started", "hook_progress", "hook_response"] {
            let frame = json!({"type":"system","subtype":subtype,"session_id":"fixed-session","uuid":"event-id","hook_id":"hook-id","hook_name":"configured hook","hook_event":"SessionStart","stdout":"untrusted output","stderr":"","output":"untrusted output","outcome":"success","exit_code":0});
            let mut p = Claude::new("/tmp/trusted".into(), "fixed-session".into());
            assert!(p.event(frame.clone()).unwrap().is_empty());
            assert_eq!(p.state, OwnerState::Starting);
            assert_eq!(p.stage, 0);
            assert!(!p.confirmed);
            let mut p = initialized();
            let sent = submitted(&mut p);
            assert!(p.event(frame.clone()).unwrap().is_empty());
            assert_eq!(p.state, OwnerState::ActiveTurn);
            assert_eq!(p.pending.as_ref().unwrap().uuid, sent["uuid"]);
            assert!(!p.confirmed);
            for (key, value) in [
                ("session_id", json!("replacement")),
                ("uuid", Value::Null),
                ("hook_id", Value::Null),
                ("hook_name", json!({})),
                ("hook_event", json!("unknown")),
                ("parent_tool_use_id", json!("child")),
                ("agent_id", json!("child")),
            ] {
                let mut wrong = frame.clone();
                wrong[key] = value;
                assert!(p.event(wrong).is_err(), "admitted invalid {key}");
            }
            p.state = OwnerState::Revoked;
            assert!(p.event(frame).is_err());
        }
    }
    #[test]
    fn javascript_trim_cannot_hide_a_context_command_from_admission() {
        for prefix in [
            "\u{feff}",
            " \u{feff}\t",
            "\u{feff}\n",
            "\u{a0}\u{feff}\u{2028}",
            "\u{2007}\u{feff}\u{3000}",
        ] {
            for command in ["/clear", "/resume other", "/compact", "/fork", "/plan"] {
                for origin in [
                    SubmissionOrigin::Local(1),
                    SubmissionOrigin::Remote("request".into()),
                ] {
                    let mut p = initialized();
                    let effects = p.submit(origin, format!("{prefix}{command}"));
                    assert!(effects.iter().all(|e| !matches!(e, Effect::Write(_))));
                    assert!(
                        matches!(&effects[0], Effect::Result(_, SubmissionOutcome::Rejected { code }) if code == "invalid_text")
                    );
                    assert_eq!(p.state, OwnerState::AwaitingSessionConfirmation);
                }
            }
        }
        let mut p = initialized();
        let text = "\u{feff}ordinary text\n /not-a-leading-command";
        assert_eq!(
            write(p.submit(SubmissionOrigin::Local(1), text.into()))["message"]["content"],
            text
        );
    }
    #[test]
    fn bootstrap_is_local_once_and_acceptance_requires_full_replay_not_completion() {
        let mut p = initialized();
        assert!(
            matches!(&p.submit(SubmissionOrigin::Remote("r".into()), "x".into())[0], Effect::Result(_, SubmissionOutcome::Rejected { code }) if code == "unsupported_recipient")
        );
        let message = submitted(&mut p);
        assert!(
            matches!(&p.submit(SubmissionOrigin::Local(2), "second".into())[0], Effect::Result(_, SubmissionOutcome::Rejected { code }) if code == "queue_full")
        );
        assert!(p
            .event(json!({"type":"result","session_id":"fixed-session","subtype":"success"}))
            .is_err());
        let effects = p.event(replay(message.clone())).unwrap();
        assert!(
            matches!(&effects[0], Effect::Result(SubmissionOrigin::Local(1), SubmissionOutcome::Accepted { submission_id }) if submission_id == message["uuid"].as_str().unwrap())
        );
        assert_eq!(p.state, OwnerState::ActiveTurn);
        assert!(
            matches!(&p.submit(SubmissionOrigin::Local(2), "second".into())[0], Effect::Result(_, SubmissionOutcome::Rejected { code }) if code == "not_ready")
        );
        p.event(json!({"type":"result","session_id":"fixed-session","subtype":"success"}))
            .unwrap();
        assert_eq!(p.state, OwnerState::Idle);
        assert_ne!(submitted(&mut p)["uuid"], message["uuid"]);
    }
    #[test]
    fn replay_rejects_wrong_uuid_session_parent_role_text_missing_fields_and_synthetic() {
        for (field, value) in [
            ("uuid", json!("other")),
            ("session_id", json!("other")),
            ("parent_tool_use_id", json!("tool")),
            ("isReplay", json!(false)),
            ("isSynthetic", json!(true)),
            (
                "message",
                json!({"role":"assistant","content":"  exact\ntext ' \"  "}),
            ),
            ("message", json!({"role":"user","content":"exact"})),
            (
                "message",
                json!({"role":"user","content":[{"type":"text","text":"  exact\ntext ' \"  "}]}),
            ),
        ] {
            let mut p = initialized();
            let mut message = replay(submitted(&mut p));
            message[field] = value;
            assert!(p.event(message).is_err(), "accepted mismatched {field}");
            assert!(p.pending.is_some());
        }
        for field in [
            "uuid",
            "session_id",
            "parent_tool_use_id",
            "isReplay",
            "message",
        ] {
            let mut p = initialized();
            let mut message = replay(submitted(&mut p));
            message.as_object_mut().unwrap().remove(field);
            assert!(p.event(message).is_err(), "accepted missing {field}");
        }
    }
    #[test]
    fn startup_version_initialization_and_session_metadata_fail_closed() {
        let mut p = Claude::new("/tmp/trusted".into(), "fixed-session".into());
        assert!(
            matches!(&p.submit(SubmissionOrigin::Local(1), "x".into())[0], Effect::Result(_, SubmissionOutcome::Rejected { code }) if code == "not_ready")
        );
        assert!(p.event(json!({"type":"control_response","response":{"subtype":"success","request_id":"initialize","response":{}}})).is_err());
        p.stage = 1;
        for version in ["2.1.275", "2.1.277", ""] {
            assert!(p.event(json!({"type":"control_response","response":{"subtype":"success","request_id":"version","response":{"version":version}}})).is_err());
        }
        for (field, value) in [
            ("session_id", "other"),
            ("cwd", "/other"),
            ("claude_code_version", "2.1.277"),
        ] {
            let mut p = initialized();
            let mut event = json!({"type":"system","subtype":"init","uuid":"init-metadata","session_id":"fixed-session","cwd":"/tmp/trusted","claude_code_version":VERSION,"permissionMode":"default"});
            event[field] = json!(value);
            assert!(p.event(event).is_err());
        }
    }
    #[test]
    fn original_consent_input_is_returned_unchanged_and_cancellation_invalidates_cards() {
        let mut p = initialized();
        submitted(&mut p);
        let input = json!({"command":"printf 'a\\nb'","description":"test","timeout":2000});
        p.event(request("permission", "Bash", input.clone()))
            .unwrap();
        assert!(p.cards()[0].details.contains("printf"));
        assert!(p
            .decision(&json!("permission"), "allow_for_session")
            .is_empty());
        let reply = write(p.decision(&json!("permission"), "allow"));
        assert_eq!(
            reply["response"]["response"],
            json!({"behavior":"allow","updatedInput":input})
        );
        assert_eq!(reply["response"]["request_id"], "permission");
        assert!(p.decision(&json!("permission"), "allow").is_empty());
        p.event(request(
            "cancelled",
            "Write",
            json!({"file_path":"scratch","content":"x"}),
        ))
        .unwrap();
        p.event(json!({"type":"control_cancel_request","request_id":"cancelled"}))
            .unwrap();
        assert!(p.decision(&json!("cancelled"), "allow").is_empty());
        assert!(p.event(request("permission", "Bash", json!({}))).is_err());
    }
    #[test]
    fn actual_questions_collect_answers_without_generic_allow_or_permission_grants() {
        let mut p = initialized();
        submitted(&mut p);
        let input = json!({"questions":[{"question":"Which?","header":"Pick","multiSelect":false,"options":[{"label":"one","description":"first"},{"label":"two","description":"second"}]}]});
        let mut req = request("question", "AskUserQuestion", input.clone());
        req["request"]["requires_user_interaction"] = json!(true);
        p.event(req).unwrap();
        assert!(p.cards()[0].details.contains("Which?"));
        for invalid in ["allow", "0", "3", "1,2", "{}", "{\"Other?\":\"one\"}"] {
            assert!(p.decision(&json!("question"), invalid).is_empty());
        }
        let reply = write(p.decision(&json!("question"), "2"));
        let mut expected = input.clone();
        expected["answers"] = json!({"Which?":"two"});
        assert_eq!(
            reply["response"]["response"],
            json!({"behavior":"allow","updatedInput":expected})
        );
        p.event(request("free", "AskUserQuestion", input)).unwrap();
        let reply = write(p.decision(&json!("free"), "{\"Which?\":\"custom answer\"}"));
        assert_eq!(
            reply["response"]["response"]["updatedInput"]["answers"]["Which?"],
            "custom answer"
        );
    }
    #[test]
    fn unsupported_oversized_plan_mcp_and_local_only_consent_never_offer_allow() {
        let mut p = initialized();
        submitted(&mut p);
        for (i, tool) in [
            "EnterPlanMode",
            "ExitPlanMode",
            "mcp__server__tool",
            "Unknown",
        ]
        .into_iter()
        .enumerate()
        {
            let reply = write(
                p.event(request(&format!("unknown-{i}"), tool, json!({})))
                    .unwrap(),
            );
            assert_eq!(reply["response"]["response"]["behavior"], "deny");
            assert!(p.cards().is_empty());
        }
        for (i, (field, value)) in [
            ("requires_user_interaction", json!(true)),
            ("unreviewedPolicy", json!(true)),
            ("agent_id", json!("child")),
        ]
        .into_iter()
        .enumerate()
        {
            let mut req = request(
                &format!("field-{i}"),
                "Bash",
                json!({"command":"echo safe"}),
            );
            req["request"][field] = value;
            assert_eq!(
                write(p.event(req).unwrap())["response"]["response"]["behavior"],
                "deny"
            );
        }
        let reply = write(
            p.event(request(
                "oversize",
                "Write",
                json!({"content":"x".repeat(17000)}),
            ))
            .unwrap(),
        );
        assert_eq!(reply["response"]["response"]["behavior"], "deny");
        assert!(p.cards().is_empty());
        assert!(p.event(json!({"type":"control_request","request_id":"dialog","request":{"subtype":"request_user_dialog","dialog_kind":"unknown","payload":{}}})).is_err());
    }
    #[test]
    fn reset_and_control_flood_retire_without_manufactured_acknowledgment() {
        for frame in [
            json!({"type":"conversation_reset","new_conversation_id":"other"}),
            json!({"type":"system","subtype":"conversation_reset","session_id":"fixed-session"}),
        ] {
            let mut p = initialized();
            submitted(&mut p);
            assert!(p.event(frame).is_err());
            assert!(p.pending.is_some());
        }
        let mut p = initialized();
        submitted(&mut p);
        for i in 0..16 {
            p.event(request(
                &i.to_string(),
                "Bash",
                json!({"command":"echo safe"}),
            ))
            .unwrap();
        }
        assert_eq!(p.cards().len(), 16);
        assert!(p.event(request("overflow", "Bash", json!({}))).is_err());
    }
    fn tool_result() -> Value {
        json!({"type":"user","session_id":"fixed-session","uuid":"tool-output","parent_tool_use_id":null,"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"tool-permission","content":"safe","is_error":false}]},"tool_use_result":{"stdout":"safe"}})
    }
    fn rate_limit() -> Value {
        json!({"type":"rate_limit_event","session_id":"fixed-session","uuid":"rate","rate_limit_info":{"status":"allowed_warning","rateLimitType":"five_hour","utilization":0.9}})
    }
    fn progress() -> Value {
        json!({"type":"tool_progress","session_id":"fixed-session","uuid":"progress","tool_use_id":"tool-permission","tool_name":"Bash","parent_tool_use_id":null,"elapsed_time_seconds":1.5,"heartbeat":true})
    }
    #[test]
    fn ordinary_tool_output_never_acknowledges_or_unlocks_input() {
        for denied in [false, true] {
            let mut p = initialized();
            let input = submitted(&mut p);
            let mut output = tool_result();
            output["message"]["content"][0]["is_error"] = json!(denied);
            assert!(p.event(output.clone()).unwrap().is_empty());
            assert!(p.pending.is_some());
            p.event(replay(input)).unwrap();
            assert!(p.event(output).unwrap().is_empty());
            assert_eq!(p.state, OwnerState::ActiveTurn);
            assert!(matches!(
                &p.submit(SubmissionOrigin::Local(2), "blocked".into())[0],
                Effect::Result(_, SubmissionOutcome::Rejected { .. })
            ));
            p.event(json!({"type":"result","session_id":"fixed-session","subtype":"success"}))
                .unwrap();
            assert_eq!(p.state, OwnerState::Idle);
            submitted(&mut p);
        }
    }
    #[test]
    fn ordinary_information_preserves_bootstrap_pending_permission_and_active_admission() {
        let mut p = initialized();
        assert!(p.event(rate_limit()).unwrap().is_empty());
        assert_eq!(p.state, OwnerState::AwaitingSessionConfirmation);
        let input = submitted(&mut p);
        for event in [rate_limit(), progress()] {
            assert!(p.event(event).unwrap().is_empty());
            assert!(p.pending.is_some());
        }
        p.event(replay(input)).unwrap();
        p.event(request(
            "permission",
            "Bash",
            json!({"command":"printf safe"}),
        ))
        .unwrap();
        for event in [rate_limit(), progress()] {
            assert!(p.event(event).unwrap().is_empty());
            assert_eq!(p.state, OwnerState::PendingPermission);
        }
    }
    #[test]
    fn settlements_echo_exactly_once_without_accepting_input() {
        for decision in ["allow", "deny"] {
            let mut p = initialized();
            let input = submitted(&mut p);
            p.event(request(
                "permission",
                "Bash",
                json!({"command":"printf safe"}),
            ))
            .unwrap();
            let reply = write(p.decision(&json!("permission"), decision));
            assert!(p.event(reply.clone()).unwrap().is_empty());
            assert!(p.pending.is_some());
            assert_eq!(p.state, OwnerState::ActiveTurn);
            assert!(p.event(reply).is_err());
            p.event(replay(input)).unwrap();
        }
    }
    #[test]
    fn ordinary_output_rejects_malformed_identity_unknown_and_reset_envelopes() {
        for event in [tool_result(), rate_limit(), progress()] {
            for (key, value) in [
                ("session_id", json!("other")),
                ("uuid", json!(null)),
                ("parent_tool_use_id", json!("subagent")),
                ("agent_id", json!("child")),
            ] {
                let mut p = initialized();
                submitted(&mut p);
                let mut bad = event.clone();
                bad[key] = value;
                assert!(p.event(bad).is_err(), "accepted {key} on {event}");
                assert!(p.pending.is_some());
            }
        }
        for event in [
            json!({"type":"user","session_id":"fixed-session","uuid":"output","parent_tool_use_id":null,"message":{"role":"user","content":"not a replay"}}),
            json!({"type":"tool_progress","session_id":"fixed-session","uuid":"progress","parent_tool_use_id":null,"tool_name":"Bash","tool_use_id":"t","elapsed_time_seconds":-1}),
            json!({"type":"rate_limit_event","session_id":"fixed-session","uuid":"rate","rate_limit_info":{"status":"unknown"}}),
            json!({"type":"system","session_id":"fixed-session","uuid":"system","subtype":"unknown"}),
            json!({"type":"system","session_id":"fixed-session","uuid":"system","subtype":"conversation_reset"}),
            json!({"type":"system","session_id":"fixed-session","uuid":"system","subtype":"compact_boundary"}),
            json!({"type":"system","session_id":"fixed-session","uuid":"system","subtype":"model_consent_fallback"}),
        ] {
            let mut p = initialized();
            submitted(&mut p);
            assert!(p.event(event).is_err());
            assert!(p.pending.is_some());
        }
    }
    #[test]
    fn settlement_mismatch_fabrication_cancellation_expiry_and_bound_fail_closed() {
        for field in ["request_id", "subtype", "response"] {
            let mut p = initialized();
            submitted(&mut p);
            p.event(request(
                "permission",
                "Bash",
                json!({"command":"printf safe"}),
            ))
            .unwrap();
            let reply = write(p.decision(&json!("permission"), "allow"));
            let mut bad = reply.clone();
            bad["response"][field] = json!("fabricated");
            assert!(p.event(bad).is_err());
            assert_eq!(p.settlements.len(), 1);
            assert!(p.event(reply).unwrap().is_empty());
        }
        let mut p = initialized();
        let input = submitted(&mut p);
        p.event(request("cancelled", "Bash", json!({}))).unwrap();
        p.event(json!({"type":"control_cancel_request","request_id":"cancelled"}))
            .unwrap();
        assert!(p
            .event(permission_response(
                "cancelled",
                json!({"behavior":"allow","updatedInput":{}})
            ))
            .is_err());
        // Optional error echoes must match exactly, and may be absent entirely.
        let error = write(p.event(json!({"type":"control_request","request_id":"unsupported","request":{"subtype":"unknown"}})).unwrap());
        assert!(p.event(error.clone()).unwrap().is_empty());
        assert!(p.event(error).is_err());
        let pending_error = write(p.event(json!({"type":"control_request","request_id":"unechoed","request":{"subtype":"unknown"}})).unwrap());
        p.event(replay(input)).unwrap();
        p.event(json!({"type":"result","session_id":"fixed-session","subtype":"success"}))
            .unwrap();
        assert!(p.settlements.is_empty());
        submitted(&mut p);
        assert!(p.event(pending_error).is_err());
        for n in 0..16 {
            p.event(request(&format!("denied-{n}"), "Unknown", json!({})))
                .unwrap();
        }
        assert_eq!(p.settlements.len(), 16);
        assert!(p.event(request("overflow", "Unknown", json!({}))).is_err());
    }
    #[test]
    fn repeated_pinned_init_and_allowlisted_system_information_do_not_change_admission() {
        let mut p = initialized();
        let init = json!({"type":"system","subtype":"init","uuid":"init-metadata","session_id":"fixed-session","cwd":"/tmp/trusted","claude_code_version":VERSION,"permissionMode":"default"});
        for _ in 0..2 {
            let input = submitted(&mut p);
            p.event(init.clone()).unwrap();
            assert_eq!(p.state, OwnerState::ActiveTurn);
            assert!(p.pending.is_some());
            for body in [
                json!({"subtype":"status","status":null}),
                json!({"subtype":"notification","key":"n","text":"notice","priority":"low"}),
                json!({"subtype":"api_retry","attempt":1,"max_retries":3,"retry_delay_ms":100,"error_status":null,"error":"overloaded"}),
                json!({"subtype":"thinking_tokens","estimated_tokens":10,"estimated_tokens_delta":2}),
                json!({"subtype":"memory_recall","mode":"select","memories":[{"path":"/tmp/memory","scope":"personal"}]}),
                json!({"subtype":"model_fallback","trigger":"overloaded","original_model":"a","fallback_model":"b","content":"fallback"}),
                json!({"subtype":"model_refusal_no_fallback","original_model":"a","content":"declined","request_id":null}),
            ] {
                let mut event = body;
                event["type"] = json!("system");
                event["session_id"] = json!("fixed-session");
                event["uuid"] = json!("info");
                assert!(p.event(event).unwrap().is_empty());
                assert!(p.pending.is_some());
            }
            assert!(p.event(json!({"type":"tool_use_summary","session_id":"fixed-session","uuid":"summary","summary":"safe","preceding_tool_use_ids":["tool"]})).unwrap().is_empty());
            p.event(replay(input)).unwrap();
            p.event(json!({"type":"result","session_id":"fixed-session","subtype":"success"}))
                .unwrap();
        }
        for field in ["session_id", "cwd", "claude_code_version"] {
            let mut bad = init.clone();
            bad[field] = json!("changed");
            assert!(p.event(bad).is_err());
        }
    }
    #[test]
    fn defensive_settlement_overflow_permanently_revokes_without_writes() {
        let mut p = initialized();
        let input = submitted(&mut p);
        p.event(replay(input)).unwrap();
        p.event(request("permission", "Bash", json!({"command":"safe"})))
            .unwrap();
        // White-box corruption: valid displayed cards are much smaller. Exercise
        // the defensive byte-bound path without relaxing real consent validation.
        p.cards.get_mut("permission").unwrap().params["input"] =
            json!({"command":"x".repeat(64 * 1024)});
        let effects = p.decision(&json!("permission"), "allow");
        assert!(!effects
            .iter()
            .any(|effect| matches!(effect, Effect::Write(_))));
        assert_eq!(p.state, OwnerState::Revoked);
        assert!(p.cards.is_empty());
        assert!(p.settlements.is_empty());
        assert!(p.decision(&json!("permission"), "allow").is_empty());
        assert!(p
            .event(json!({"type":"result","session_id":"fixed-session","subtype":"success"}))
            .is_err());
        assert!(!p
            .submit(SubmissionOrigin::Local(2), "never send".into())
            .iter()
            .any(|effect| matches!(effect, Effect::Write(_))));
        assert_eq!(p.state, OwnerState::Revoked);
    }
    #[test]
    fn launch_is_fixed_session_typed_and_preserves_policy() {
        let session = fresh_uuid().unwrap();
        assert_eq!(session.len(), 36);
        assert_eq!(&session[14..15], "4");
        assert_ne!(session, fresh_uuid().unwrap());
        let command = Claude::command(&session);
        let args: Vec<_> = command.get_args().map(|s| s.to_str().unwrap()).collect();
        assert_eq!(
            args,
            [
                "--print",
                "--input-format",
                "stream-json",
                "--output-format",
                "stream-json",
                "--verbose",
                "--replay-user-messages",
                "--session-id",
                &session,
                "--permission-prompt-tool",
                "stdio",
                "--disallowedTools",
                "EnterPlanMode,ExitPlanMode"
            ]
        );
        assert!(command.get_envs().next().is_none());
    }
}
