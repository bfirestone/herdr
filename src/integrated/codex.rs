//! Codex 0.154.0 app-server stdio protocol; one process and one fixed thread.
use super::{
    approvals::Approvals,
    identity::valid_text,
    owner::{OwnerState, SubmissionOutcome},
};
use serde_json::{json, Value};
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum SubmissionOrigin {
    Remote(String),
    Local(u64),
}

pub(super) enum Effect {
    Write(Value),
    Result(SubmissionOrigin, SubmissionOutcome),
    Text(String),
    State(OwnerState),
}
struct Pending {
    provider_id: String,
    request_id: SubmissionOrigin,
}
pub(super) struct Codex {
    cwd: String,
    stage: u8,
    thread: Option<String>,
    turn: Option<String>,
    pending: Option<Pending>,
    items: HashMap<String, Value>,
    pub approvals: Approvals,
    pub state: OwnerState,
}
impl Codex {
    pub fn new(cwd: String) -> Self {
        Self {
            cwd,
            stage: 0,
            thread: None,
            turn: None,
            pending: None,
            items: HashMap::new(),
            approvals: Approvals::default(),
            state: OwnerState::Starting,
        }
    }
    pub fn initialize() -> Value {
        json!({"id":"initialize","method":"initialize","params":{"clientInfo":{"name":"herdr","version":env!("CARGO_PKG_VERSION")},"capabilities":{"experimentalApi":true}}})
    }
    pub fn submit(&mut self, id: SubmissionOrigin, text: String) -> Vec<Effect> {
        let rejection = if !valid_text(&text) {
            Some("invalid_text")
        } else if self.pending.is_some() {
            Some("queue_full")
        } else if self.state != OwnerState::Idle {
            Some("not_ready")
        } else {
            None
        };
        if let Some(code) = rejection {
            return vec![
                Effect::Result(id, SubmissionOutcome::rejected(code)),
                Effect::State(self.state),
            ];
        }
        let Ok(nonce) = crate::platform::recipient_random() else {
            return vec![Effect::Result(
                id,
                SubmissionOutcome::rejected("revoked_before_write"),
            )];
        };
        let provider_id = format!("turn-{nonce}");
        self.pending = Some(Pending {
            provider_id: provider_id.clone(),
            request_id: id,
        });
        self.state = OwnerState::ActiveTurn;
        vec![
            Effect::State(self.state),
            Effect::Write(json!({"id":provider_id,"method":"turn/start","params":{
                "threadId":self.thread,"clientUserMessageId":nonce,"input":[{"type":"text","text":text}]
            }})),
        ]
    }
    pub fn event(&mut self, frame: Value) -> Result<Vec<Effect>, ()> {
        if let Some(method) = frame["method"].as_str() {
            let params = &frame["params"];
            let announced = params["threadId"]
                .as_str()
                .or_else(|| params["thread"]["id"].as_str());
            if let Some(thread) = announced {
                if let Some(expected) = &self.thread {
                    if thread != expected {
                        return Err(());
                    }
                } else if self.stage == 1 && method == "thread/started" {
                    self.thread = Some(thread.into());
                } else {
                    return Err(());
                }
            }
            if method.contains("reset")
                || method.contains("resumed")
                || method.starts_with("thread/realtime")
                || method.contains("rollback")
                || matches!(
                    method,
                    "thread/closed" | "thread/archived" | "thread/unarchived"
                )
            {
                return Err(());
            }
            if frame.get("id").is_some() {
                if self.approvals.at_capacity() || self.approvals.previously_seen(&frame["id"]) {
                    return Err(());
                }
                if method == "mcpServer/elicitation/request"
                    && (self.turn.is_none() || params["turnId"].is_null())
                {
                    return Ok(vec![
                        Effect::Text("Uncorrelated standalone MCP elicitation declined.\n".into()),
                        Effect::Write(
                            json!({"id":frame["id"],"result":{"action":"decline","content":null}}),
                        ),
                    ]);
                }
                if !matches!(
                    method,
                    "item/commandExecution/requestApproval"
                        | "item/fileChange/requestApproval"
                        | "item/permissions/requestApproval"
                        | "item/tool/requestUserInput"
                        | "mcpServer/elicitation/request"
                ) {
                    return Ok(vec![
                        Effect::Text("Unsupported provider interaction denied.\n".into()),
                        Effect::Write(
                            json!({"id":frame["id"],"error":{"code":-32601,"message":"Unsupported integrated interaction"}}),
                        ),
                    ]);
                }
                let turn = self.turn.as_deref().ok_or(())?;
                if params["turnId"] != turn {
                    return Err(());
                }
                let item = params["itemId"].as_str().and_then(|id| self.items.get(id));
                if self
                    .approvals
                    .insert(&frame, self.thread.as_deref().ok_or(())?, turn, item)
                    .is_err()
                {
                    // Unsupported/auth/disclosure requests never get a generic Allow.
                    return Ok(vec![
                        Effect::Text("Unsupported or incomplete provider request denied.\n".into()),
                        Effect::Write(if method == "mcpServer/elicitation/request" {
                            json!({"id":frame["id"],"result":{"action":"decline","content":null}})
                        } else {
                            json!({"id":frame["id"],"error":{"code":-32601,"message":"Unsupported integrated interaction"}})
                        }),
                    ]);
                }
                self.state = OwnerState::PendingPermission;
                return Ok(vec![Effect::State(self.state)]);
            }
            if let Some(turn) = params["turnId"].as_str() {
                if self.turn.as_deref() != Some(turn) {
                    return Err(());
                }
            }
            match method {
                "turn/started" => {
                    let turn = params["turn"]["id"].as_str().ok_or(())?;
                    if self.pending.is_none() && self.turn.as_deref() != Some(turn) {
                        return Err(());
                    }
                    if self.turn.as_deref().is_some_and(|t| t != turn) {
                        return Err(());
                    }
                    self.turn = Some(turn.into());
                }
                "turn/completed" => {
                    if self.pending.is_some()
                        || self.turn.as_deref() != params["turn"]["id"].as_str()
                    {
                        return Err(());
                    }
                    self.turn = None;
                    self.approvals.clear();
                    self.items.clear();
                    self.state = OwnerState::Idle;
                    return Ok(vec![
                        Effect::State(self.state),
                        Effect::Text("\n[turn completed]\n".into()),
                    ]);
                }
                "serverRequest/resolved" => {
                    self.approvals.resolve(&params["requestId"]);
                    if self.approvals.is_empty() {
                        self.state = OwnerState::ActiveTurn;
                        return Ok(vec![Effect::State(self.state)]);
                    }
                }
                "item/started" => {
                    let item = &params["item"];
                    let id = item["id"].as_str().ok_or(())?;
                    if item.to_string().len() > 64 * 1024 || self.items.len() >= 16 {
                        return Err(());
                    }
                    self.items.insert(id.into(), item.clone());
                }
                "item/completed" => {
                    if let Some(id) = params["item"]["id"].as_str() {
                        self.items.remove(id);
                    }
                }
                "item/agentMessage/delta"
                | "item/commandExecution/outputDelta"
                | "item/reasoning/textDelta" => {
                    return Ok(vec![Effect::Text(
                        params["delta"].as_str().ok_or(())?.into(),
                    )]);
                }
                _ => {}
            }
            return Ok(vec![]);
        }
        if frame.get("error").is_some() {
            return Err(());
        }
        let id = frame["id"].as_str().ok_or(())?;
        let result = &frame["result"];
        match self.stage {
            0 => {
                if id != "initialize"
                    || result["userAgent"].as_str().is_none_or(|version| {
                        version
                            .split_whitespace()
                            .next()
                            .and_then(|prefix| prefix.rsplit_once('/'))
                            .map(|(_, version)| version)
                            != Some("0.154.0")
                    })
                {
                    return Err(());
                }
                self.stage = 1;
                Ok(vec![
                    Effect::Write(json!({"method":"initialized"})),
                    Effect::Write(
                        json!({"id":"thread","method":"thread/start","params":{"cwd":self.cwd}}),
                    ),
                ])
            }
            1 => {
                if id != "thread"
                    || result["cwd"] != self.cwd
                    || result.get("approvalPolicy").is_none()
                    || result.get("sandbox").is_none()
                {
                    return Err(());
                }
                let thread = result["thread"]["id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or(())?;
                if self.thread.as_deref().is_some_and(|t| t != thread) {
                    return Err(());
                }
                self.thread = Some(thread.into());
                self.stage = 2;
                self.state = OwnerState::Idle;
                Ok(vec![Effect::Text(format!("Codex integrated — fixed thread {thread}\nApproval policy: {}\nSandbox: {}\nExact delivery remains unqualified pending provider proof.\n", result["approvalPolicy"], result["sandbox"])),Effect::State(self.state)])
            }
            _ => {
                let pending = self.pending.as_ref().ok_or(())?;
                if id != pending.provider_id {
                    return Err(());
                }
                let turn = result["turn"]["id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or(())?;
                if self.turn.as_deref().is_some_and(|t| t != turn) {
                    return Err(());
                }
                self.turn = Some(turn.into());
                let pending = self.pending.take().unwrap();
                Ok(vec![Effect::Result(
                    pending.request_id,
                    SubmissionOutcome::Accepted {
                        submission_id: turn.into(),
                    },
                )])
            }
        }
    }
    pub fn decision(&mut self, id: &Value, decision: &str) -> Vec<Effect> {
        let Some(response) = self.approvals.decide(id, decision) else {
            return vec![Effect::Text(
                "Decision is invalid or request already resolved.\n".into(),
            )];
        };
        self.state = if self.approvals.is_empty() {
            OwnerState::ActiveTurn
        } else {
            OwnerState::PendingPermission
        };
        vec![Effect::Write(response), Effect::State(self.state)]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready() -> Codex {
        let mut codex = Codex::new("/tmp".into());
        codex
            .event(json!({"id":"initialize","result":{"userAgent":"codex/0.154.0"}}))
            .unwrap();
        codex.event(json!({"id":"thread","result":{"thread":{"id":"t"},"cwd":"/tmp","approvalPolicy":"on-request","sandbox":{"type":"readOnly"}}})).unwrap();
        codex
    }
    #[test]
    fn accepts_only_matching_turn_reply_and_never_steers_busy_turn() {
        let mut codex = ready();
        let effects = codex.submit(SubmissionOrigin::Remote("a".into()), "hello".into());
        let Effect::Write(request) = &effects[1] else {
            panic!()
        };
        assert_eq!(request["params"]["threadId"], "t");
        assert!(!codex
            .submit(SubmissionOrigin::Remote("b".into()), "hello".into())
            .iter()
            .any(|e| matches!(e, Effect::Write(_))));
        let result = codex
            .event(json!({"id":request["id"],"result":{"turn":{"id":"u"}}}))
            .unwrap();
        assert!(
            matches!(&result[0], Effect::Result(id, SubmissionOutcome::Accepted {..}) if id == &SubmissionOrigin::Remote("a".into()))
        );
        assert!(codex
            .event(json!({"id":request["id"],"result":{"turn":{"id":"u"}}}))
            .is_err());
        assert!(codex.event(json!({"method":"item/agentMessage/delta","params":{"threadId":"other","delta":"bad"}})).is_err());
    }
    #[test]
    fn standalone_mcp_and_auth_are_visibly_declined_without_acceptance() {
        let mut codex = ready();
        let effects = codex.event(json!({"id":8,"method":"mcpServer/elicitation/request","params":{"threadId":"t","turnId":null,"serverName":"fixture","mode":"form","message":"standalone","requestedSchema":{"type":"object","properties":{"x":{"type":"string"}}}}})).unwrap();
        assert!(matches!(&effects[0], Effect::Text(_)));
        let Effect::Write(response) = &effects[1] else {
            panic!()
        };
        assert_eq!(response["result"]["action"], "decline");
        assert!(codex.approvals.is_empty());
        let effects = codex
            .event(json!({"id":9,"method":"account/login/request","params":{}}))
            .unwrap();
        assert!(matches!(&effects[0], Effect::Text(_)));
    }
    #[test]
    fn local_and_remote_request_names_cannot_collide() {
        let mut codex = ready();
        let local = codex.submit(SubmissionOrigin::Local(1), "local text".into());
        let Effect::Write(request) = &local[1] else {
            panic!()
        };
        let remote = codex.submit(
            SubmissionOrigin::Remote("local-1".into()),
            "remote text".into(),
        );
        assert!(
            matches!(&remote[0],Effect::Result(SubmissionOrigin::Remote(id),SubmissionOutcome::Rejected{..}) if id=="local-1")
        );
        let ack = codex
            .event(json!({"id":request["id"],"result":{"turn":{"id":"local-turn"}}}))
            .unwrap();
        assert!(matches!(
            &ack[0],
            Effect::Result(
                SubmissionOrigin::Local(1),
                SubmissionOutcome::Accepted { .. }
            )
        ));
    }
}
