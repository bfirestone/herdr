#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct RecipientIdentity {
    pub server_instance: String,
    pub recipient_token: String,
    pub terminal_id: String,
}

pub(super) fn valid_text(text: &str) -> bool {
    text.len() <= 65536
        && !text.trim().is_empty()
        && !text.contains('\0')
        && !text.trim_start().starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_empty_nul_slash_and_oversize_without_normalizing_valid_text() {
        for text in ["", " \n", "x\0y", " /new", "/resume x", &"é".repeat(32769)] {
            assert!(!valid_text(text), "invalid input admitted");
        }
        assert!(valid_text("  hello\nworld  "));
        assert!(valid_text(&"é".repeat(32768)));
    }
}
