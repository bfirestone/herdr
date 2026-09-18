use super::{
    channel::{read_frame, write_frame, CONTROL_LIMIT, INPUT_LIMIT},
    identity::{valid_text, RecipientIdentity},
};
use crate::platform::{RecipientBootstrap, RecipientStream};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    io::BufReader,
    sync::{mpsc, Arc, Mutex, OnceLock},
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OwnerState {
    Starting,
    Idle,
    ActiveTurn,
    PendingPermission,
    OutcomeUnknown,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub(crate) enum SubmissionOutcome {
    Accepted { submission_id: String },
    Rejected { code: String },
    Unknown,
}
impl SubmissionOutcome {
    pub(super) fn rejected(code: &str) -> Self {
        Self::Rejected { code: code.into() }
    }
}

struct Pending {
    id: String,
    attempted: bool,
    sender: mpsc::SyncSender<SubmissionOutcome>,
}
struct State {
    phase: OwnerState,
    seen: HashSet<String>,
    pending: Option<Pending>,
}

/// Owns exactly one accepted stream. OnceLock has no replacement/rebind path.
pub(crate) struct Owner {
    pub identity: RecipientIdentity,
    stream: OnceLock<RecipientStream>,
    state: Mutex<State>,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
    observed: std::sync::Condvar,
}
impl Owner {
    pub(crate) fn launch(
        identity: RecipientIdentity,
        bootstrap: RecipientBootstrap,
        pid: u32,
    ) -> Arc<Self> {
        let owner = Arc::new(Self {
            identity,
            stream: OnceLock::new(),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            observed: std::sync::Condvar::new(),
            state: Mutex::new(State {
                phase: OwnerState::Starting,
                seen: HashSet::new(),
                pending: None,
            }),
        });
        let weak = Arc::downgrade(&owner);
        let cancelled = owner.cancelled.clone();
        std::thread::spawn(move || {
            let run = || -> std::io::Result<()> {
                let mut stream = bootstrap.accept(pid, &cancelled)?;
                let Some(owner) = weak.upgrade() else {
                    return Ok(());
                };
                let state = owner.state.lock().unwrap();
                if state.phase != OwnerState::Starting {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                write_frame(&mut stream, &owner.identity, CONTROL_LIMIT)?;
                owner
                    .stream
                    .set(stream.try_clone()?)
                    .map_err(|_| std::io::Error::other("already bound"))?;
                drop(state);
                drop(owner);
                let mut reader = BufReader::new(stream);
                loop {
                    let frame = read_frame(&mut reader, CONTROL_LIMIT)?;
                    let Some(owner) = weak.upgrade() else {
                        return Ok(());
                    };
                    owner.receive(frame)?;
                }
            };
            let _ = run();
            if let Some(owner) = weak.upgrade() {
                owner.revoke();
            }
        });
        owner
    }

    pub(crate) fn state(&self) -> OwnerState {
        self.state.lock().unwrap().phase
    }

    /// Admission is synchronous and bounded; only the admitted request gets a waiter.
    pub(crate) fn reserve(
        &self,
        identity: &RecipientIdentity,
        id: &str,
        text: &str,
    ) -> Result<mpsc::Receiver<SubmissionOutcome>, SubmissionOutcome> {
        let mut state = self.state.lock().unwrap();
        let reject = |code| Err(SubmissionOutcome::rejected(code));
        if identity != &self.identity {
            return reject("stale_recipient");
        }
        if state.phase == OwnerState::Revoked {
            return reject("revoked_before_write");
        }
        if !valid_text(text) || id.is_empty() || id.len() > 256 {
            return reject("invalid_text");
        }
        if state.pending.is_some() || state.seen.contains(id) || state.seen.len() >= 4096 {
            return reject("queue_full");
        }
        if state.phase != OwnerState::Idle {
            return reject("not_ready");
        }
        if self.stream.get().is_none() {
            return reject("not_ready");
        }
        let (tx, rx) = mpsc::sync_channel(1);
        state.seen.insert(id.to_owned());
        state.pending = Some(Pending {
            id: id.into(),
            attempted: false,
            sender: tx,
        });
        state.phase = OwnerState::ActiveTurn;
        Ok(rx)
    }

    pub(crate) fn forward(&self, id: &str, text: &str) {
        {
            let mut state = self.state.lock().unwrap();
            if state.phase == OwnerState::Revoked {
                return;
            }
            let Some(pending) = state.pending.as_mut() else {
                return;
            };
            if pending.id != id || pending.attempted {
                return;
            }
            pending.attempted = true;
        }
        let Some(stream) = self.stream.get() else {
            self.revoke();
            return;
        };
        let frame =
            serde_json::json!({"kind":"submit", "identity": self.identity, "id":id, "text":text});
        let mut writer = stream;
        if write_frame(&mut writer, &frame, INPUT_LIMIT).is_err() {
            self.revoke();
        }
    }

    fn receive(&self, frame: serde_json::Value) -> std::io::Result<()> {
        let invalid = || {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid integrated control frame",
            )
        };
        let identity: RecipientIdentity =
            serde_json::from_value(frame["identity"].clone()).map_err(|_| invalid())?;
        if identity != self.identity {
            return Err(invalid());
        }
        let mut state = self.state.lock().unwrap();
        if state.phase == OwnerState::Revoked {
            return Err(invalid());
        }
        match frame["kind"].as_str() {
            Some("state") => {
                let phase: OwnerState =
                    serde_json::from_value(frame["state"].clone()).map_err(|_| invalid())?;
                if phase == OwnerState::Starting
                    || state.pending.is_some() && phase == OwnerState::Idle
                {
                    return Err(invalid());
                }
                state.phase = phase;
            }
            Some("result") => {
                if state.pending.as_ref().map(|p| p.id.as_str()) != frame["id"].as_str()
                    || state.pending.as_ref().is_none_or(|p| !p.attempted)
                {
                    return Err(invalid());
                }
                let outcome: SubmissionOutcome =
                    serde_json::from_value(frame["result"].clone()).map_err(|_| invalid())?;
                if let SubmissionOutcome::Rejected { code } = &outcome {
                    if !matches!(
                        code.as_str(),
                        "queue_full"
                            | "not_ready"
                            | "invalid_text"
                            | "stale_recipient"
                            | "revoked_before_write"
                    ) {
                        return Err(invalid());
                    }
                }
                let pending = state.pending.take().unwrap();
                let _ = pending.sender.send(outcome);
            }
            _ => return Err(invalid()),
        }
        self.observed.notify_all();
        Ok(())
    }

    pub(crate) fn revoke(&self) {
        self.cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        let mut state = self.state.lock().unwrap();
        if let Some(pending) = state.pending.take() {
            let _ = pending.sender.send(if pending.attempted {
                SubmissionOutcome::Unknown
            } else {
                SubmissionOutcome::rejected("revoked_before_write")
            });
        }
        state.phase = OwnerState::Revoked;
        self.observed.notify_all();
        if let Some(stream) = self.stream.get() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    pub(crate) fn wait(&self, receiver: mpsc::Receiver<SubmissionOutcome>) -> SubmissionOutcome {
        match receiver.recv_timeout(Duration::from_secs(15)) {
            Ok(outcome) => outcome,
            Err(_) => {
                self.revoke();
                SubmissionOutcome::Unknown
            }
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.revoke();
    }
}

/// Runtime lifetime, independent of attached TUI clients. Dropping or handing off
/// a pane revokes before its runtime can be replaced.
pub(crate) struct OwnerLease(pub(super) Arc<Owner>);
impl Drop for OwnerLease {
    fn drop(&mut self) {
        self.0.revoke();
    }
}
impl Owner {
    pub(crate) fn lease(self: &Arc<Self>) -> OwnerLease {
        OwnerLease(self.clone())
    }
}

#[cfg(test)]
impl Owner {
    pub(super) fn wait_for_phase(&self, phase: OwnerState) {
        let state = self.state.lock().unwrap();
        let (state, timeout) = self
            .observed
            .wait_timeout_while(state, Duration::from_secs(10), |s| s.phase != phase)
            .unwrap();
        let actual = state.phase;
        drop(state);
        assert!(!timeout.timed_out(), "expected {phase:?}, got {actual:?}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    fn connected() -> Option<(Owner, RecipientStream)> {
        let (stream, peer) = crate::platform::recipient_test_pair().ok()?;
        let owner = Owner {
            identity: RecipientIdentity {
                server_instance: "s".into(),
                recipient_token: "r".into(),
                terminal_id: "t".into(),
            },
            stream: OnceLock::from(stream),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            observed: std::sync::Condvar::new(),
            state: Mutex::new(State {
                phase: OwnerState::Idle,
                seen: HashSet::new(),
                pending: None,
            }),
        };
        Some((owner, peer))
    }
    #[test]
    fn stale_identities_and_queued_replacement_receive_zero_bytes() {
        let Some((owner, mut peer)) = connected() else {
            return;
        };
        for identity in [
            RecipientIdentity {
                server_instance: "wrong".into(),
                ..owner.identity.clone()
            },
            RecipientIdentity {
                recipient_token: "wrong".into(),
                ..owner.identity.clone()
            },
            RecipientIdentity {
                terminal_id: "wrong".into(),
                ..owner.identity.clone()
            },
        ] {
            assert_eq!(
                owner.reserve(&identity, "q", "secret").unwrap_err(),
                SubmissionOutcome::rejected("stale_recipient")
            );
        }
        let first = owner.reserve(&owner.identity, "q", "secret").unwrap();
        assert_eq!(
            owner
                .reserve(&owner.identity, "q2", "replacement")
                .unwrap_err(),
            SubmissionOutcome::rejected("queue_full")
        );
        owner.revoke();
        owner.revoke();
        owner.forward("q", "secret");
        assert_eq!(
            first.recv().unwrap(),
            SubmissionOutcome::rejected("revoked_before_write")
        );
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
        let (replacement, mut replacement_peer) = crate::platform::recipient_test_pair().unwrap();
        assert!(owner.stream.set(replacement).is_err());
        assert_eq!(replacement_peer.read(&mut [0u8; 1]).unwrap(), 0);
    }
    #[test]
    fn attempted_write_disconnect_and_mismatched_ack_are_unknown() {
        let Some((owner, mut peer)) = connected() else {
            return;
        };
        let first = owner.reserve(&owner.identity, "q", "secret").unwrap();
        owner.forward("q", "secret");
        let frame = read_frame(&mut BufReader::new(&mut peer), INPUT_LIMIT).unwrap();
        assert_eq!(frame["text"], "secret");
        assert!(owner.receive(serde_json::json!({"kind":"result","identity":owner.identity,"id":"wrong","result":{"outcome":"accepted","submission_id":"turn"}})).is_err());
        owner.revoke();
        assert_eq!(first.recv().unwrap(), SubmissionOutcome::Unknown);
        assert_eq!(
            owner.reserve(&owner.identity, "q2", "secret").unwrap_err(),
            SubmissionOutcome::rejected("revoked_before_write")
        );
    }
    #[test]
    fn matching_ack_is_accepted_and_request_id_cannot_be_reused() {
        let Some((owner, _peer)) = connected() else {
            return;
        };
        let first = owner.reserve(&owner.identity, "q", "secret").unwrap();
        owner.forward("q", "secret");
        owner.receive(serde_json::json!({"kind":"result","identity":owner.identity,"id":"q","result":{"outcome":"accepted","submission_id":"turn"}})).unwrap();
        assert_eq!(
            first.recv().unwrap(),
            SubmissionOutcome::Accepted {
                submission_id: "turn".into()
            }
        );
        owner
            .receive(serde_json::json!({"kind":"state","identity":owner.identity,"state":"idle"}))
            .unwrap();
        assert_eq!(
            owner.reserve(&owner.identity, "q", "secret").unwrap_err(),
            SubmissionOutcome::rejected("queue_full")
        );
    }
}
