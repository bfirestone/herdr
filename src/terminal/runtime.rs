use std::sync::Arc;

use crate::render_signal::RenderSignal;

use bytes::Bytes;
use ratatui::{layout::Rect, Frame};
use tokio::sync::{mpsc, Notify};

use crate::events::AppEvent;
use crate::layout::PaneId;

/// Live runtime for a server-owned terminal.
///
/// The PTY implementation still delegates to the legacy pane runtime while the
/// migration proceeds, but production code now depends on this terminal-layer
/// type instead of the pane module's implementation detail.
pub struct TerminalRuntime {
    // Drop the delivery lease before shutting down the helper PTY.
    integrated_owner: Option<crate::integrated::OwnerLease>,
    runtime: crate::pane::PaneRuntime,
}

impl TerminalRuntime {
    fn new_inner(runtime: crate::pane::PaneRuntime) -> Self {
        Self {
            integrated_owner: None,
            runtime,
        }
    }
    pub(crate) fn bind_integrated_owner(&mut self, lease: crate::integrated::OwnerLease) {
        self.integrated_owner = Some(lease);
    }

    pub fn shutdown(self) {
        drop(self.integrated_owner);
        self.runtime.shutdown();
    }

    #[cfg(unix)]
    pub fn duplicate_handoff_fd(&self) -> std::io::Result<std::os::fd::RawFd> {
        self.runtime.duplicate_handoff_fd()
    }

    #[cfg(unix)]
    pub fn preserve_for_handoff(self) {
        drop(self.integrated_owner);
        self.runtime.preserve_for_handoff()
    }

    #[cfg(unix)]
    pub fn assume_handoff_ownership(&mut self) {
        self.runtime.assume_handoff_ownership();
    }

    #[cfg(unix)]
    pub fn set_handoff_reader_paused(&self, paused: bool) {
        self.runtime.set_handoff_reader_paused(paused);
    }

    #[cfg(unix)]
    pub fn pause_handoff_reader(&self, timeout: std::time::Duration) -> std::io::Result<()> {
        self.runtime.pause_handoff_reader(timeout)
    }

    #[cfg(unix)]
    pub fn handoff_runtime_state(
        &self,
        pane_id: u32,
    ) -> crate::handoff_runtime::HandoffRuntimeState {
        self.runtime.handoff_runtime_state(pane_id)
    }

    #[cfg(unix)]
    pub fn handoff_history_ansi(&self) -> Option<String> {
        self.runtime.handoff_history_ansi()
    }

    #[cfg(unix)]
    pub fn from_handoff_fd(
        import: crate::handoff_runtime::ImportedHandoffRuntime,
        scrollback_limit_bytes: usize,
        host_terminal_theme: crate::terminal_theme::TerminalTheme,
        host_terminal_appearance: Option<crate::terminal_theme::HostAppearance>,
        events: mpsc::Sender<AppEvent>,
        render_notify: Arc<Notify>,
        render_dirty: Arc<RenderSignal>,
    ) -> std::io::Result<Self> {
        crate::pane::PaneRuntime::from_handoff_fd(
            import,
            scrollback_limit_bytes,
            host_terminal_theme,
            host_terminal_appearance,
            events,
            render_notify,
            render_dirty,
        )
        .map(Self::new_inner)
    }

    // Wrapper mirrors pane runtime construction arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        pane_id: PaneId,
        rows: u16,
        cols: u16,
        cwd: std::path::PathBuf,
        scrollback_limit_bytes: usize,
        host_terminal_theme: crate::terminal_theme::TerminalTheme,
        host_terminal_appearance: Option<crate::terminal_theme::HostAppearance>,
        shell_config: crate::pane::PaneShellConfig<'_>,
        launch_env: &crate::pane::PaneLaunchEnv,
        events: mpsc::Sender<AppEvent>,
        render_notify: Arc<Notify>,
        render_dirty: Arc<RenderSignal>,
    ) -> std::io::Result<Self> {
        crate::pane::PaneRuntime::spawn(
            pane_id,
            rows,
            cols,
            cwd,
            scrollback_limit_bytes,
            host_terminal_theme,
            host_terminal_appearance,
            shell_config,
            launch_env,
            events,
            render_notify,
            render_dirty,
        )
        .map(Self::new_inner)
    }

    // Wrapper mirrors pane runtime construction arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_with_initial_history(
        pane_id: PaneId,
        rows: u16,
        cols: u16,
        cwd: std::path::PathBuf,
        scrollback_limit_bytes: usize,
        host_terminal_theme: crate::terminal_theme::TerminalTheme,
        host_terminal_appearance: Option<crate::terminal_theme::HostAppearance>,
        shell_config: crate::pane::PaneShellConfig<'_>,
        launch_env: &crate::pane::PaneLaunchEnv,
        initial_history_ansi: Option<&str>,
        events: mpsc::Sender<AppEvent>,
        render_notify: Arc<Notify>,
        render_dirty: Arc<RenderSignal>,
    ) -> std::io::Result<Self> {
        crate::pane::PaneRuntime::spawn_with_initial_history(
            pane_id,
            rows,
            cols,
            cwd,
            scrollback_limit_bytes,
            host_terminal_theme,
            host_terminal_appearance,
            shell_config,
            launch_env,
            initial_history_ansi,
            events,
            render_notify,
            render_dirty,
        )
        .map(Self::new_inner)
    }

    // Wrapper mirrors pane runtime construction arguments.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_shell_command(
        pane_id: PaneId,
        rows: u16,
        cols: u16,
        cwd: std::path::PathBuf,
        command: &str,
        launch_env: &crate::pane::PaneLaunchEnv,
        agent_detection: crate::pane::AgentDetection,
        scrollback_limit_bytes: usize,
        host_terminal_theme: crate::terminal_theme::TerminalTheme,
        host_terminal_appearance: Option<crate::terminal_theme::HostAppearance>,
        events: mpsc::Sender<AppEvent>,
        render_notify: Arc<Notify>,
        render_dirty: Arc<RenderSignal>,
    ) -> std::io::Result<Self> {
        crate::pane::PaneRuntime::spawn_shell_command(
            pane_id,
            rows,
            cols,
            cwd,
            command,
            launch_env,
            agent_detection,
            scrollback_limit_bytes,
            host_terminal_theme,
            host_terminal_appearance,
            events,
            render_notify,
            render_dirty,
        )
        .map(Self::new_inner)
    }

    // Wrapper mirrors pane runtime construction arguments, including detection policy.
    #[allow(clippy::too_many_arguments)]
    pub fn spawn_argv_command(
        pane_id: PaneId,
        rows: u16,
        cols: u16,
        cwd: std::path::PathBuf,
        argv: &[String],
        launch_env: &crate::pane::PaneLaunchEnv,
        agent_detection: crate::pane::AgentDetection,
        scrollback_limit_bytes: usize,
        host_terminal_theme: crate::terminal_theme::TerminalTheme,
        host_terminal_appearance: Option<crate::terminal_theme::HostAppearance>,
        events: mpsc::Sender<AppEvent>,
        render_notify: Arc<Notify>,
        render_dirty: Arc<RenderSignal>,
    ) -> std::io::Result<Self> {
        crate::pane::PaneRuntime::spawn_argv_command(
            pane_id,
            rows,
            cols,
            cwd,
            argv,
            launch_env,
            agent_detection,
            scrollback_limit_bytes,
            host_terminal_theme,
            host_terminal_appearance,
            events,
            render_notify,
            render_dirty,
        )
        .map(Self::new_inner)
    }

    pub fn apply_host_terminal_theme(&self, theme: crate::terminal_theme::TerminalTheme) {
        self.runtime.apply_host_terminal_theme(theme);
    }

    pub fn apply_host_terminal_appearance(
        &self,
        appearance: Option<crate::terminal_theme::HostAppearance>,
    ) {
        self.runtime.apply_host_terminal_appearance(appearance);
    }

    pub fn begin_graceful_release(&self, agent: crate::detect::Agent) {
        self.runtime.begin_graceful_release(agent);
    }

    pub fn reset_agent_detection(&self) {
        self.runtime.reset_agent_detection();
    }

    #[cfg(test)]
    pub(crate) fn agent_detection_reset_notify_for_test(
        &self,
    ) -> std::sync::Arc<tokio::sync::Notify> {
        self.runtime.agent_detection_reset_notify_for_test()
    }

    pub fn set_full_lifecycle_authority_active(&self, active: bool) {
        self.runtime.set_full_lifecycle_authority_active(active);
    }

    pub fn resize(&self, rows: u16, cols: u16, cell_width_px: u32, cell_height_px: u32) {
        self.runtime
            .resize(rows, cols, cell_width_px, cell_height_px);
    }

    #[cfg(unix)]
    pub fn nudge_child_redraw_after_handoff(&self) {
        self.runtime.nudge_child_redraw_after_handoff();
    }

    pub fn scroll_up(&self, lines: usize) {
        self.runtime.scroll_up(lines);
    }

    pub fn scroll_down(&self, lines: usize) {
        self.runtime.scroll_down(lines);
    }

    pub fn scroll_reset(&self) {
        self.runtime.scroll_reset();
    }

    pub fn set_scroll_offset_from_bottom(&self, lines: usize) {
        self.runtime.set_scroll_offset_from_bottom(lines);
    }

    pub fn scroll_metrics(&self) -> Option<crate::pane::ScrollMetrics> {
        self.runtime.scroll_metrics()
    }

    pub(crate) fn search_text_window(
        &self,
        query: &str,
        case_sensitive: bool,
        direction: crate::pane::TerminalSearchDirection,
        cursor: crate::pane::TerminalTextPoint,
        previous: Option<(
            crate::pane::TerminalTextPoint,
            crate::pane::TerminalTextPoint,
        )>,
        limit: usize,
    ) -> crate::pane::TerminalSearchWindow {
        self.runtime
            .search_text_window(query, case_sensitive, direction, cursor, previous, limit)
    }

    pub(crate) fn word_motion_target(
        &self,
        row: u32,
        col: u16,
        motion: crate::pane::TerminalWordMotion,
    ) -> Option<crate::pane::TerminalTextPoint> {
        self.runtime.word_motion_target(row, col, motion)
    }

    pub(crate) fn terminal_dimensions(&self) -> Option<(u16, u16)> {
        self.runtime.terminal_dimensions()
    }

    pub(crate) fn paragraph_motion_target(
        &self,
        row: u32,
        direction: i8,
    ) -> Option<crate::pane::TerminalTextPoint> {
        self.runtime.paragraph_motion_target(row, direction)
    }

    pub fn bracketed_paste_enabled(&self) -> bool {
        self.runtime.bracketed_paste_enabled()
    }

    pub fn mouse_reporting_enabled(&self) -> bool {
        self.runtime.mouse_reporting_enabled()
    }

    pub fn sgr_pixel_mouse_enabled(&self) -> bool {
        self.runtime.sgr_pixel_mouse_enabled()
    }

    pub fn plain_page_keys_use_host_scrollback(&self) -> Option<bool> {
        self.runtime.plain_page_keys_use_host_scrollback()
    }

    /// Reads only whether the alternate screen is active.
    pub fn alternate_screen_active(&self) -> bool {
        self.runtime.alternate_screen_active()
    }

    pub fn cursor_state(
        &self,
        area: Rect,
        show_cursor: bool,
    ) -> Option<crate::pane::TerminalCursorState> {
        self.runtime.cursor_state(area, show_cursor)
    }

    pub fn synchronized_output_active(&self) -> bool {
        self.runtime.synchronized_output_active()
    }

    pub fn visible_text(&self) -> String {
        self.runtime.visible_text()
    }

    pub fn visible_ansi(&self) -> String {
        self.runtime.visible_ansi()
    }

    pub fn detection_text(&self) -> String {
        self.runtime.detection_text()
    }

    pub fn terminal_title(&self) -> Option<String> {
        self.runtime.terminal_title()
    }

    pub fn agent_osc_title(&self) -> String {
        self.runtime.agent_osc_title()
    }

    pub fn agent_osc_progress(&self) -> String {
        self.runtime.agent_osc_progress()
    }

    pub(crate) fn recent_text_snapshot(&self, lines: usize) -> crate::pane::TerminalReadSnapshot {
        self.runtime.recent_text_snapshot(lines)
    }

    pub(crate) fn recent_ansi_snapshot(&self, lines: usize) -> crate::pane::TerminalReadSnapshot {
        self.runtime.recent_ansi_snapshot(lines)
    }

    #[cfg(test)]
    pub fn recent_unwrapped_text(&self, lines: usize) -> String {
        self.runtime.recent_unwrapped_text_snapshot(lines).text
    }

    pub(crate) fn recent_unwrapped_text_snapshot(
        &self,
        lines: usize,
    ) -> crate::pane::TerminalReadSnapshot {
        self.runtime.recent_unwrapped_text_snapshot(lines)
    }

    pub(crate) fn recent_unwrapped_ansi_snapshot(
        &self,
        lines: usize,
    ) -> crate::pane::TerminalReadSnapshot {
        self.runtime.recent_unwrapped_ansi_snapshot(lines)
    }

    pub fn snapshot_history(&self) -> Option<String> {
        self.runtime.snapshot_history()
    }

    pub fn extract_selection(&self, selection: &crate::selection::Selection) -> Option<String> {
        self.runtime.extract_selection(selection)
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, show_cursor: bool) {
        self.runtime.render(frame, area, show_cursor);
    }

    pub(crate) fn collect_dirty_patch_snapshot(
        &self,
        area_width: u16,
        area_height: u16,
    ) -> Option<crate::pane::TerminalDirtyPatchSnapshot> {
        self.runtime
            .collect_dirty_patch_snapshot(area_width, area_height)
    }

    pub fn visible_hyperlinks(&self, area: Rect) -> Vec<((u16, u16), String, String)> {
        self.runtime.visible_hyperlinks(area)
    }

    pub(crate) fn link_regions_at(
        &self,
        col: u16,
        row: u16,
        resolve: fn(&str, usize) -> Option<std::ops::Range<usize>>,
    ) -> Vec<crate::api::schema::PaneLinkRegion> {
        self.runtime.link_regions_at(col, row, resolve)
    }

    pub(crate) fn link_target_at(&self, col: u16, row: u16) -> Option<crate::ghostty::LinkTarget> {
        self.runtime.link_target_at(col, row)
    }

    pub fn kitty_image_placements_with_data_filter<F>(
        &self,
        needs_data: F,
    ) -> Vec<crate::ghostty::KittyImagePlacement>
    where
        F: FnMut(crate::ghostty::KittyImageDescriptor) -> bool,
    {
        self.runtime
            .kitty_image_placements_with_data_filter(needs_data)
    }

    pub fn keyboard_protocol(&self) -> crate::input::KeyboardProtocol {
        self.runtime.keyboard_protocol()
    }

    pub fn modify_other_keys_level(&self) -> u8 {
        self.runtime.modify_other_keys_level()
    }

    pub fn encode_terminal_key(&self, key: crate::input::TerminalKey) -> Vec<u8> {
        self.runtime.encode_terminal_key(key)
    }

    pub fn try_send_bytes(&self, bytes: Bytes) -> Result<(), mpsc::error::TrySendError<Bytes>> {
        self.runtime.try_send_bytes(bytes)
    }

    pub fn queue_user_input_submission(
        &self,
        text: Bytes,
        enter: Bytes,
        delay: std::time::Duration,
        deadline: Option<std::time::Instant>,
    ) -> std::io::Result<std::sync::mpsc::Receiver<std::io::Result<()>>> {
        self.runtime
            .queue_user_input_submission(text, enter, delay, deadline)
    }

    pub fn try_send_paste(&self, text: String) -> Result<(), mpsc::error::TrySendError<Bytes>> {
        self.runtime.try_send_paste(text)
    }

    pub fn try_send_focus_event(&self, event: crate::ghostty::FocusEvent) -> bool {
        self.runtime.try_send_focus_event(event)
    }

    pub fn wheel_routing(&self) -> Option<crate::pane::WheelRouting> {
        self.runtime.wheel_routing()
    }

    pub(crate) fn screen_text_snapshot(
        &self,
    ) -> Option<(
        crate::ghostty::ActiveScreen,
        crate::terminal::ScreenSnapshot,
    )> {
        let (screen, cols, rows) = self.runtime.screen_text_snapshot()?;
        Some((screen, crate::terminal::ScreenSnapshot { cols, rows }))
    }

    pub(crate) fn screen_text_snapshot_with_seq(
        &self,
    ) -> Option<(
        crate::ghostty::ActiveScreen,
        crate::terminal::ScreenSnapshot,
        u64,
    )> {
        for _ in 0..3 {
            let before = self.content_seq();
            if !before.is_multiple_of(2) {
                continue;
            }
            let (screen, snapshot) = self.screen_text_snapshot()?;
            let after = self.content_seq();
            if before == after {
                return Some((screen, snapshot, after));
            }
        }
        None
    }

    pub fn encode_mouse_button(
        &self,
        kind: crossterm::event::MouseEventKind,
        position: crate::input::mouse::Position,
        modifiers: crossterm::event::KeyModifiers,
    ) -> Option<Vec<u8>> {
        self.runtime.encode_mouse_button(kind, position, modifiers)
    }

    pub(crate) fn encode_mouse_motion(
        &self,
        kind: crossterm::event::MouseEventKind,
        position: crate::input::mouse::Position,
        modifiers: crossterm::event::KeyModifiers,
    ) -> Option<Vec<u8>> {
        self.runtime.encode_mouse_motion(kind, position, modifiers)
    }

    pub(crate) fn encode_mouse_wheel(
        &self,
        kind: crossterm::event::MouseEventKind,
        position: crate::input::mouse::Position,
        modifiers: crossterm::event::KeyModifiers,
    ) -> Option<Vec<u8>> {
        self.runtime.encode_mouse_wheel(kind, position, modifiers)
    }

    pub(crate) fn pixel_size(&self) -> Option<(u32, u32)> {
        self.runtime.pixel_size()
    }

    pub fn encode_alternate_scroll(
        &self,
        kind: crossterm::event::MouseEventKind,
    ) -> Option<Vec<u8>> {
        self.runtime.encode_alternate_scroll(kind)
    }

    pub fn cwd(&self) -> Option<std::path::PathBuf> {
        self.runtime.cwd()
    }

    pub fn follow_cwd(&self) -> Option<std::path::PathBuf> {
        self.runtime.follow_cwd()
    }

    pub fn foreground_cwd(&self) -> Option<std::path::PathBuf> {
        self.runtime.foreground_cwd()
    }

    pub fn child_pid(&self) -> Option<u32> {
        self.runtime.child_pid()
    }

    pub(crate) fn current_size(&self) -> (u16, u16) {
        self.runtime.current_size()
    }

    pub(crate) fn content_seq(&self) -> u64 {
        self.runtime.content_seq()
    }
}

#[cfg(test)]
impl TerminalRuntime {
    pub(crate) fn test_contend_during_dirty_collection(
        &self,
        bytes: Vec<u8>,
    ) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<bool>) {
        self.runtime.test_contend_during_dirty_collection(bytes)
    }

    pub(crate) fn test_with_channel(cols: u16, rows: u16) -> (Self, mpsc::Receiver<Bytes>) {
        let (runtime, rx) = crate::pane::PaneRuntime::test_with_channel(cols, rows);
        (Self::new_inner(runtime), rx)
    }

    pub(crate) fn test_with_channel_capacity(
        cols: u16,
        rows: u16,
        capacity: usize,
    ) -> (Self, mpsc::Receiver<Bytes>) {
        let (runtime, rx) =
            crate::pane::PaneRuntime::test_with_channel_capacity(cols, rows, capacity);
        (Self::new_inner(runtime), rx)
    }

    pub(crate) fn test_with_screen_bytes(cols: u16, rows: u16, bytes: &[u8]) -> Self {
        Self::new_inner(crate::pane::PaneRuntime::test_with_screen_bytes(
            cols, rows, bytes,
        ))
    }

    pub(crate) fn test_process_pty_bytes(&self, bytes: &[u8]) {
        self.runtime.test_process_pty_bytes(bytes);
    }

    pub(crate) fn test_with_scrollback_bytes(
        cols: u16,
        rows: u16,
        scrollback_limit_bytes: usize,
        bytes: &[u8],
    ) -> Self {
        Self::new_inner(crate::pane::PaneRuntime::test_with_scrollback_bytes(
            cols,
            rows,
            scrollback_limit_bytes,
            bytes,
        ))
    }

    pub(crate) fn test_with_channel_and_scrollback_bytes(
        cols: u16,
        rows: u16,
        scrollback_limit_bytes: usize,
        bytes: &[u8],
        channel_capacity: usize,
    ) -> (Self, mpsc::Receiver<Bytes>) {
        let (runtime, rx) = crate::pane::PaneRuntime::test_with_channel_and_scrollback_bytes(
            cols,
            rows,
            scrollback_limit_bytes,
            bytes,
            channel_capacity,
        );
        (Self::new_inner(runtime), rx)
    }
}
