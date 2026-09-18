//! Approval decisions are bound to a complete, current provider operation.
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashSet};

#[derive(Clone)]
pub(super) struct Card {
    pub id: Value,
    pub method: String,
    pub params: Value,
    pub details: String,
}
#[derive(Default)]
pub(super) struct Approvals {
    cards: BTreeMap<String, Card>,
    seen: HashSet<String>,
}
impl Approvals {
    pub fn insert(
        &mut self,
        request: &Value,
        thread: &str,
        turn: &str,
        item: Option<&Value>,
    ) -> Result<(), ()> {
        let params = &request["params"];
        let id = &request["id"];
        let method = request["method"].as_str().ok_or(())?;
        if !(id.is_string() || id.is_i64())
            || params["threadId"] != thread
            || params["turnId"] != turn
            || (method != "mcpServer/elicitation/request"
                && params["itemId"].as_str().is_none_or(str::is_empty))
            || self.cards.len() >= 16
            || self.seen.contains(&id.to_string())
            || self.seen.len() >= 4096
        {
            return Err(());
        }
        let common = ["threadId", "turnId", "itemId", "startedAtMs"];
        let allowed: &[&str] = match method {
            "item/commandExecution/requestApproval" => &[
                "command",
                "cwd",
                "kind",
                "approvalId",
                "environmentId",
                "reason",
                "networkApprovalContext",
                "commandActions",
                "additionalPermissions",
                "availableDecisions",
                "proposedExecpolicyAmendment",
                "proposedNetworkPolicyAmendments",
            ],
            "item/fileChange/requestApproval" => &["grantRoot", "reason"],
            "item/permissions/requestApproval" => {
                &["cwd", "environmentId", "permissions", "reason"]
            }
            "item/tool/requestUserInput" => &["questions", "isBlocking", "autoResolutionMs"],
            "mcpServer/elicitation/request" => {
                &["serverName", "mode", "message", "requestedSchema", "_meta"]
            }
            _ => return Err(()),
        };
        if params
            .as_object()
            .ok_or(())?
            .keys()
            .any(|key| !common.contains(&key.as_str()) && !allowed.contains(&key.as_str()))
        {
            return Err(());
        }
        if matches!(
            method,
            "item/commandExecution/requestApproval"
                | "item/fileChange/requestApproval"
                | "item/permissions/requestApproval"
        ) && !params["startedAtMs"].is_i64()
        {
            return Err(());
        }
        if method == "item/tool/requestUserInput" && !params["isBlocking"].is_boolean() {
            return Err(());
        }
        match method {
            "item/commandExecution/requestApproval" => {
                if params["command"].as_str().is_none()
                    || params["cwd"].as_str().is_none()
                    || params["kind"].as_str().is_some_and(|k| k != "command")
                    || params["availableDecisions"]
                        .as_array()
                        .is_some_and(|options| !options.contains(&json!("accept")))
                {
                    return Err(());
                }
            }
            "item/fileChange/requestApproval" => {
                let item = item.ok_or(())?;
                if item["type"] != "fileChange"
                    || item["id"] != params["itemId"]
                    || item["changes"].as_array().is_none_or(|changes| {
                        changes.is_empty()
                            || changes.iter().any(|change| {
                                change["path"].as_str().is_none()
                                    || change["diff"].as_str().is_none()
                                    || !matches!(
                                        change["kind"]["type"].as_str(),
                                        Some("add" | "delete" | "update")
                                    )
                            })
                    })
                    || !params["grantRoot"].is_null()
                {
                    return Err(());
                }
            }
            "item/permissions/requestApproval" => {
                if !params["permissions"].is_object() || params["cwd"].as_str().is_none() {
                    return Err(());
                }
            }
            "mcpServer/elicitation/request" => {
                if params["mode"] != "form"
                    || !params["_meta"].is_null()
                    || params["serverName"].as_str().is_none_or(str::is_empty)
                    || params["message"].as_str().is_none()
                    || !supported_form(&params["requestedSchema"])
                {
                    return Err(());
                }
            }
            "item/tool/requestUserInput" => {
                let questions = params["questions"].as_array().ok_or(())?;
                if questions.is_empty()
                    || questions.len() > 3
                    || questions.iter().any(|q| {
                        q["isSecret"] == true
                            || q["id"].as_str().is_none()
                            || q["question"].as_str().is_none()
                            || q["options"]
                                .as_array()
                                .is_none_or(|o| o.is_empty() || o.len() > 9)
                    })
                {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
        let details = serde_json::to_string_pretty(&json!({"request":request,"operation":item}))
            .map_err(|_| ())?;
        // Whole details are displayed; never approve a truncated operation.
        if super::render::sanitize(&details).len() > 16 * 1024 {
            return Err(());
        }
        self.seen.insert(id.to_string());
        self.cards.insert(
            id.to_string(),
            Card {
                id: id.clone(),
                method: method.into(),
                params: params.clone(),
                details,
            },
        );
        Ok(())
    }
    pub fn resolve(&mut self, id: &Value) {
        self.cards.remove(&id.to_string());
    }
    pub fn cards(&self) -> Vec<Card> {
        self.cards.values().cloned().collect()
    }
    pub fn at_capacity(&self) -> bool {
        self.cards.len() >= 16 || self.seen.len() >= 4096
    }
    pub fn previously_seen(&self, id: &Value) -> bool {
        self.seen.contains(&id.to_string())
    }
    pub fn is_empty(&self) -> bool {
        self.cards.is_empty()
    }
    pub fn clear(&mut self) {
        self.cards.clear();
    }

    pub fn decide(&mut self, id: &Value, decision: &str) -> Option<Value> {
        let card = self.cards.get(&id.to_string())?;
        let result = match card.method.as_str() {
            "mcpServer/elicitation/request" => match decision {
                "deny" => json!({"action":"decline","content":null}),
                "cancel" => json!({"action":"cancel","content":null}),
                _ => {
                    let content: Value = serde_json::from_str(decision).ok()?;
                    if !valid_form_content(&card.params["requestedSchema"], &content) {
                        return None;
                    }
                    json!({"action":"accept","content":content})
                }
            },
            "item/permissions/requestApproval" => {
                if !matches!(decision, "allow" | "deny" | "cancel") {
                    return None;
                }
                json!({"permissions":if decision == "allow" { card.params["permissions"].clone() } else {json!({})},"scope":"turn"})
            }
            "item/tool/requestUserInput" => {
                if decision == "deny" || decision == "cancel" {
                    json!({"answers":{}})
                } else {
                    let indices: Vec<usize> = decision
                        .split(',')
                        .map(str::parse)
                        .collect::<Result<_, _>>()
                        .ok()?;
                    let questions = card.params["questions"].as_array()?;
                    if indices.len() != questions.len() {
                        return None;
                    }
                    let mut answers = serde_json::Map::new();
                    for (q, index) in questions.iter().zip(indices) {
                        let label = q["options"].as_array()?.get(index.checked_sub(1)?)?["label"]
                            .as_str()?;
                        answers.insert(q["id"].as_str()?.into(), json!({"answers":[label]}));
                    }
                    json!({"answers":answers})
                }
            }
            _ => {
                json!({"decision": match decision { "allow" => "accept", "deny" => "decline", "cancel" => "cancel", _ => return None }})
            }
        };
        let card = self.cards.remove(&id.to_string())?;
        Some(json!({"id":card.id,"result":result}))
    }
}

fn supported_form(schema: &Value) -> bool {
    let Some(object) = schema.as_object() else {
        return false;
    };
    let Some(properties) = schema["properties"].as_object() else {
        return false;
    };
    if schema["type"] != "object"
        || properties.is_empty()
        || properties.len() > 8
        || object
            .keys()
            .any(|k| !["type", "properties", "required", "$schema"].contains(&k.as_str()))
    {
        return false;
    }
    if let Some(required) = schema["required"].as_array() {
        if required
            .iter()
            .any(|key| key.as_str().is_none_or(|s| !properties.contains_key(s)))
        {
            return false;
        }
    } else if !schema["required"].is_null() {
        return false;
    }
    properties.values().all(|property| {
        let Some(fields) = property.as_object() else {
            return false;
        };
        if fields.keys().any(|key| {
            ![
                "type",
                "title",
                "description",
                "default",
                "minLength",
                "maxLength",
                "enum",
            ]
            .contains(&key.as_str())
        }) {
            return false;
        }
        match property["type"].as_str() {
            Some("boolean") => property["enum"].is_null(),
            Some("string") => {
                property["maxLength"].as_u64().unwrap_or(1024) <= 1024
                    && property["minLength"].as_u64().unwrap_or(0)
                        <= property["maxLength"].as_u64().unwrap_or(1024)
                    && (property["enum"].is_null()
                        || property["enum"].as_array().is_some_and(|values| {
                            !values.is_empty()
                                && values.len() <= 16
                                && values.iter().all(Value::is_string)
                        }))
            }
            _ => false,
        }
    })
}

fn valid_form_content(schema: &Value, content: &Value) -> bool {
    let Some(values) = content.as_object() else {
        return false;
    };
    let Some(properties) = schema["properties"].as_object() else {
        return false;
    };
    if schema["required"].as_array().is_some_and(|required| {
        required
            .iter()
            .any(|key| key.as_str().is_none_or(|key| !values.contains_key(key)))
    }) {
        return false;
    }
    values.iter().all(|(key, value)| {
        let Some(property) = properties.get(key) else {
            return false;
        };
        match property["type"].as_str() {
            Some("boolean") => value.is_boolean(),
            Some("string") => value.as_str().is_some_and(|text| {
                text.len() <= 4096
                    && text.chars().count() >= property["minLength"].as_u64().unwrap_or(0) as usize
                    && text.chars().count()
                        <= property["maxLength"].as_u64().unwrap_or(1024) as usize
                    && property["enum"]
                        .as_array()
                        .is_none_or(|options| options.contains(value))
            }),
            _ => false,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binds_operation_and_invalidates_resolved_cards() {
        let mut approvals = Approvals::default();
        let request = json!({"id":1,"method":"item/commandExecution/requestApproval","params":{"threadId":"a","turnId":"b","itemId":"c","startedAtMs":0,"command":"echo hi","cwd":"/tmp"}});
        assert!(approvals.insert(&request, "wrong", "b", None).is_err());
        approvals.insert(&request, "a", "b", None).unwrap();
        approvals.resolve(&json!(1));
        assert!(approvals.decide(&json!(1), "allow").is_none());
        assert!(approvals
            .insert(
                &json!({"id":2,"method":"auth/login","params":request["params"]}),
                "a",
                "b",
                None
            )
            .is_err());
    }
    #[test]
    fn cannot_approve_file_without_complete_item_or_grant_session() {
        let mut approvals = Approvals::default();
        let request = json!({"id":1,"method":"item/fileChange/requestApproval","params":{"threadId":"a","turnId":"b","itemId":"c","startedAtMs":0}});
        assert!(approvals.insert(&request, "a", "b", None).is_err());
    }
    #[test]
    fn mcp_forms_collect_values_and_deny_unknown_or_local_only_flows() {
        let mut approvals = Approvals::default();
        let mut request = json!({"id":3,"method":"mcpServer/elicitation/request","params":{
            "threadId":"a","turnId":"b","serverName":"fixture","mode":"form","message":"Choose output label",
            "requestedSchema":{"type":"object","properties":{"label":{"type":"string","maxLength":20},"enabled":{"type":"boolean"}},"required":["label","enabled"]}
        }});
        approvals.insert(&request, "a", "b", None).unwrap();
        assert!(approvals.decide(&json!(3), "allow").is_none());
        assert!(approvals
            .decide(&json!(3), r#"{"label":"hello"}"#)
            .is_none());
        let response = approvals
            .decide(&json!(3), r#"{"label":"hello","enabled":true}"#)
            .unwrap();
        assert_eq!(
            response["result"]["content"],
            json!({"label":"hello","enabled":true})
        );
        assert_eq!(response["result"]["action"], "accept");
        request["id"] = json!(4);
        request["params"]["_meta"] = json!({"localOnly":true});
        assert!(approvals.insert(&request, "a", "b", None).is_err());
        request["params"]["_meta"] = Value::Null;
        request["params"]["mode"] = json!("url");
        assert!(approvals.insert(&request, "a", "b", None).is_err());
        request["params"]["mode"] = json!("form");
        request["params"]["requestedSchema"]["properties"]["label"]["format"] = json!("password");
        assert!(approvals.insert(&request, "a", "b", None).is_err());
    }

    #[test]
    fn questions_require_real_options_and_permissions_never_persist() {
        let mut approvals = Approvals::default();
        let params = json!({"threadId":"a","turnId":"b","itemId":"c","startedAtMs":0,"isBlocking":true,"questions":[{"id":"q","question":"Pick","options":[{"label":"one","description":"first"},{"label":"two","description":"second"}]}]});
        approvals
            .insert(
                &json!({"id":1,"method":"item/tool/requestUserInput","params":params}),
                "a",
                "b",
                None,
            )
            .unwrap();
        assert!(approvals.decide(&json!(1), "allow").is_none());
        assert_eq!(
            approvals.decide(&json!(1), "2").unwrap()["result"]["answers"]["q"]["answers"],
            json!(["two"])
        );
        approvals.insert(&json!({"id":2,"method":"item/permissions/requestApproval","params":{"threadId":"a","turnId":"b","itemId":"c","startedAtMs":0,"cwd":"/tmp","permissions":{"network":{"enabled":true}}}}),"a","b",None).unwrap();
        assert!(approvals.decide(&json!(2), "allow_for_session").is_none());
        let allowed = approvals.decide(&json!(2), "allow").unwrap();
        assert_eq!(allowed["result"]["scope"], "turn");
    }

    #[test]
    fn control_cards_are_bounded_and_unknown_schema_has_no_allow() {
        let mut approvals = Approvals::default();
        let request = json!({"id":1,"method":"item/commandExecution/requestApproval","params":{"threadId":"a","turnId":"b","itemId":"c","startedAtMs":0,"command":"echo safe","cwd":"/tmp","unreviewedPolicy":true}});
        assert!(approvals.insert(&request, "a", "b", None).is_err());
        let mut request = request;
        request["params"]
            .as_object_mut()
            .unwrap()
            .remove("unreviewedPolicy");
        for id in 0..16 {
            request["id"] = json!(id);
            approvals.insert(&request, "a", "b", None).unwrap();
        }
        request["id"] = json!(16);
        assert!(approvals.at_capacity());
        assert!(approvals.insert(&request, "a", "b", None).is_err());
    }
    #[test]
    fn file_approval_preserves_complete_patch_and_refuses_session_grants() {
        let mut approvals = Approvals::default();
        let mut request = json!({"id":1,"method":"item/fileChange/requestApproval","params":{"threadId":"a","turnId":"b","itemId":"c","startedAtMs":0}});
        let item = json!({"id":"c","type":"fileChange","changes":[{"path":"/tmp/scratch","kind":{"type":"add"},"diff":"+harmless"}]});
        approvals.insert(&request, "a", "b", Some(&item)).unwrap();
        assert!(approvals.cards()[0].details.contains("+harmless"));
        assert_eq!(
            approvals.decide(&json!(1), "allow").unwrap()["result"]["decision"],
            "accept"
        );
        request["id"] = json!(2);
        request["params"]["grantRoot"] = json!("/tmp");
        assert!(approvals.insert(&request, "a", "b", Some(&item)).is_err());
    }
}
