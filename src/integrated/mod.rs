//! Owned integrated sessions; never route an exact prompt through a pane PTY.
pub(crate) const CODEX_VERSION: &str = "0.154.0";
pub(crate) const EXACT_PROMPT_VERSION: u32 = 1;
pub(crate) const EXACT_PROMPT_MAX_TEXT_BYTES: u32 = 65536;
pub(crate) const EXACT_PROMPT_GUARANTEE: &str = "recipient_instance_v1";
pub(crate) const EXACT_PROMPT_TRANSPORT: &str = "recipient_channel_v1";

mod approvals;
mod channel;
mod codex;
pub(crate) mod helper;
mod identity;
mod owner;
mod render;
pub(crate) use identity::RecipientIdentity;
pub(crate) use owner::OwnerLease;
pub(crate) use owner::{Owner, OwnerState, SubmissionOutcome};
