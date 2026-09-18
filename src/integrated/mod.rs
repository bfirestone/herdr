//! Owned integrated sessions; never route an exact prompt through a pane PTY.
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
