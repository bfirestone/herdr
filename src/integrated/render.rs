use super::approvals::Card;
use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout},
    widgets::{Block, Paragraph, Wrap},
    Terminal,
};
use std::{
    collections::VecDeque,
    io,
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

pub(super) fn sanitize(text: &str) -> String {
    text.chars()
        .flat_map(|c| {
            if c == '\n'
                || c == '\t'
                || !c.is_control()
                    && !matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                c.to_string().chars().collect::<Vec<_>>()
            } else {
                c.escape_unicode().collect()
            }
        })
        .collect()
}
#[derive(Default)]
pub(super) struct View {
    transcript: VecDeque<String>,
    bytes: usize,
    truncated: bool,
    pub cards: Vec<Card>,
    pub status: String,
    pub ended: bool,
}
impl View {
    pub fn text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let mut text = sanitize(text);
        if text.len() > 256 * 1024 {
            const MARKER: &str = "[output truncated]\n";
            let mut start = text.len() - (256 * 1024 - MARKER.len());
            while !text.is_char_boundary(start) {
                start += 1;
            }
            text = format!("{MARKER}{}", &text[start..]);
        }
        self.bytes += text.len();
        if let Some(last) = self
            .transcript
            .back_mut()
            .filter(|last| last.len() + text.len() <= 4096)
        {
            last.push_str(&text);
        } else {
            self.transcript.push_back(text);
        }
        while self.bytes > 1024 * 1024 || self.transcript.len() > 4096 {
            self.truncated = true;
            self.bytes -= self.transcript.pop_front().unwrap().len();
        }
    }
}
pub(super) enum Input {
    Text(String),
    Decision(serde_json::Value, String),
    Close,
}

/// PTY writes and keyboard reads run independently from provider/control drain.
pub(super) fn start(view: Arc<Mutex<View>>, tx: mpsc::SyncSender<Input>) {
    std::thread::spawn(move || {
        let run = || -> io::Result<()> {
            enable_raw_mode()?;
            crossterm::execute!(io::stdout(), EnterAlternateScreen)?;
            let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
            let mut composer = String::new();
            let mut composer_overflow = false;
            let mut scroll = 0u16;
            let mut displayed_card = None;
            loop {
                let (text, cards, status, ended) = {
                    let view = view.lock().unwrap();
                    // Render only a bounded tail, even though the retained transcript is larger.
                    let mut text = String::new();
                    for line in view.transcript.iter().rev() {
                        if text.len() + line.len() > 256 * 1024 {
                            break;
                        }
                        text.insert_str(0, line);
                    }
                    if view.truncated {
                        text.insert_str(0, "[earlier output truncated]\n");
                    }
                    (text, view.cards.clone(), view.status.clone(), view.ended)
                };
                let consent = cards.first();
                let card_id = consent.map(|card| card.id.clone());
                if card_id != displayed_card {
                    composer.clear();
                    composer_overflow = false;
                    scroll = 0;
                    displayed_card = card_id;
                }
                terminal.draw(|frame| {
                    let areas = Layout::vertical([Constraint::Min(2), Constraint::Length(3)]).split(frame.area());
                    let body = consent.map(|card| format!("HERDR PERMISSION — {}\n{}\n\nType allow / deny / cancel then Enter. Questions: comma-separated option numbers. MCP forms: a JSON object with the displayed field names and your values. PageUp/PageDown scroll details.", sanitize(&card.method), sanitize(&card.details))).unwrap_or(text);
                    frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: false }).scroll((scroll,0)).block(Block::bordered().title(sanitize(&status))), areas[0]);
                    frame.render_widget(Paragraph::new(if composer_overflow { "Input exceeds 64 KiB; edit before sending".into() } else { sanitize(&composer) }).block(Block::bordered().title("Enter: send • Ctrl+C: close integrated session")), areas[1]);
                })?;
                if ended {
                    break;
                }
                if event::poll(Duration::from_millis(40))? {
                    if let Event::Key(key) = event::read()? {
                        match key.code {
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                let _ = tx.try_send(Input::Close);
                                break;
                            }
                            KeyCode::PageDown => scroll = scroll.saturating_add(10),
                            KeyCode::PageUp => scroll = scroll.saturating_sub(10),
                            KeyCode::Char(c) => {
                                if composer.len() + c.len_utf8() <= 65536 {
                                    composer.push(c);
                                } else {
                                    composer_overflow = true;
                                }
                            }
                            KeyCode::Backspace => {
                                composer.pop();
                                composer_overflow = false;
                            }
                            KeyCode::Enter if !composer_overflow => {
                                let input = if let Some(card) = consent {
                                    Input::Decision(card.id.clone(), composer.clone())
                                } else {
                                    Input::Text(composer.clone())
                                };
                                if tx.try_send(input).is_ok() {
                                    composer.clear();
                                    scroll = 0;
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(())
        };
        let _ = run();
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen);
        let _ = tx.try_send(Input::Close);
    });
}
#[cfg(test)]
mod tests {
    #[test]
    fn escapes_terminal_and_bidi_controls() {
        let sanitized = super::sanitize("hello\u{1b}]52;c;secret\u{7}\u{202e}");
        assert!(!sanitized.contains('\u{1b}'));
        assert!(!sanitized.contains('\u{202e}'));
        assert!(sanitized.contains("hello"));
    }
    #[test]
    fn empty_and_tiny_deltas_cannot_grow_chunk_metadata_without_bound() {
        let mut view = super::View::default();
        for _ in 0..10000 {
            view.text("");
        }
        assert!(view.transcript.is_empty());
        for _ in 0..10000 {
            view.text("x");
        }
        assert!(view.transcript.len() <= 3);
        assert_eq!(view.bytes, 10000);
        view.text(&"界".repeat(100000));
        let last = view.transcript.back().unwrap();
        assert!(last.len() <= 256 * 1024);
        assert!(last.starts_with("[output truncated]\n"));
    }
}
