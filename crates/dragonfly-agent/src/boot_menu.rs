//! Boot Menu Module
//!
//! Implements an intelligent boot menu using Ratatui for fullscreen TUI that:
//! - Scales from embedded displays to 50-foot screens
//! - Contacts Dragonfly with a short timeout (3 seconds)
//! - Immediately boots existing OS if Dragonfly is unreachable or has no instructions
//! - Allows user to press ENTER/SPACEBAR to access an interactive menu
//!
//! Philosophy: PXE boot becomes invisible. Normal operation is fast and transparent.
//! Power users get a full toolkit without needing USB sticks or physical access.

use crate::probe::DetectedOs;
use crate::workflow::{CheckInResponse, AgentAction};
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
    execute,
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use reqwest::Client;
use serde::Deserialize;
use std::io::{stdout, Stdout};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn, debug};

/// Timeout when we have an existing OS to boot
/// 3 seconds gives the user time to react and press ENTER/SPACEBAR for the menu
const DRAGONFLY_TIMEOUT: Duration = Duration::from_secs(3);

/// Block text logo - clean, scales well
const DRAGONFLY_LOGO: &str = r#"
 ██████╗ ██████╗  █████╗  ██████╗  ██████╗ ███╗   ██╗███████╗██╗  ██╗   ██╗
 ██╔══██╗██╔══██╗██╔══██╗██╔════╝ ██╔═══██╗████╗  ██║██╔════╝██║  ╚██╗ ██╔╝
 ██║  ██║██████╔╝███████║██║  ███╗██║   ██║██╔██╗ ██║█████╗  ██║   ╚████╔╝
 ██║  ██║██╔══██╗██╔══██║██║   ██║██║   ██║██║╚██╗██║██╔══╝  ██║    ╚██╔╝
 ██████╔╝██║  ██║██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██║     ███████╗██║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚══════╝╚═╝
"#;

const SLOGAN: &str = "metal, managed";

/// Template info from server
#[derive(Debug, Clone, Deserialize)]
pub struct TemplateInfo {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// ISO info from server
#[derive(Debug, Clone, Deserialize)]
pub struct IsoInfo {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// Boot options fetched from server
#[derive(Debug, Clone, Default)]
pub struct BootOptions {
    pub templates: Vec<TemplateInfo>,
    pub isos: Vec<IsoInfo>,
}

/// Fetch available boot options from Dragonfly server
pub async fn fetch_boot_options(server_url: Option<&str>) -> BootOptions {
    let Some(url) = server_url else {
        return BootOptions::default();
    };

    let client = match Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return BootOptions::default(),
    };

    let mut options = BootOptions::default();

    // Fetch templates
    if let Ok(resp) = client.get(format!("{}/api/templates", url)).send().await {
        if let Ok(templates) = resp.json::<Vec<TemplateInfo>>().await {
            options.templates = templates;
        }
    }

    // Fetch ISOs (if endpoint exists)
    if let Ok(resp) = client.get(format!("{}/api/isos", url)).send().await {
        if let Ok(isos) = resp.json::<Vec<IsoInfo>>().await {
            options.isos = isos;
        }
    }

    options
}

/// User's menu selection
#[derive(Debug, Clone, PartialEq)]
pub enum MenuSelection {
    /// Continue booting existing OS
    BootExistingOs,
    /// Perform memory test
    MemoryTest,
    /// Wipe the disk
    Wipe,
    /// Install a new OS (template name)
    InstallOs(String),
    /// Boot an ISO (URL or cached)
    BootIso(String),
    /// Boot rescue environment
    BootRescue,
    /// Vendor diagnostics
    VendorDiagnostics,
    /// Remove this machine from Dragonfly
    RemoveFromDragonfly,
    /// Execute a workflow (from Dragonfly)
    ExecuteWorkflow(String),
    /// Wait for instructions
    Wait,
    /// Exit to shell (maintenance mode)
    ExitToShell,
}

/// Menu state
struct MenuState {
    main_list_state: ListState,
    advanced_list_state: ListState,
    in_advanced: bool,
    existing_os: Option<DetectedOs>,
    boot_options: BootOptions,
    /// Track Ctrl-C for double-tap exit
    ctrl_c_pending: bool,
    /// When the first Ctrl-C was pressed
    ctrl_c_time: Option<std::time::Instant>,
}

/// How long after first Ctrl-C to require second one (1.5 seconds)
const CTRL_C_TIMEOUT: Duration = Duration::from_millis(1500);

impl MenuState {
    fn new(existing_os: Option<DetectedOs>, boot_options: BootOptions) -> Self {
        let mut main_list_state = ListState::default();
        main_list_state.select(Some(0));
        let mut advanced_list_state = ListState::default();
        advanced_list_state.select(Some(0));

        Self {
            main_list_state,
            advanced_list_state,
            in_advanced: false,
            existing_os,
            boot_options,
            ctrl_c_pending: false,
            ctrl_c_time: None,
        }
    }

    /// Handle Ctrl-C press, returns true if should exit
    fn handle_ctrl_c(&mut self) -> bool {
        let now = std::time::Instant::now();

        if let Some(first_time) = self.ctrl_c_time {
            if now.duration_since(first_time) < CTRL_C_TIMEOUT {
                // Second Ctrl-C within timeout - exit
                return true;
            }
        }

        // First Ctrl-C or timeout expired - start new window
        self.ctrl_c_pending = true;
        self.ctrl_c_time = Some(now);
        false
    }

    /// Check if Ctrl-C prompt should be shown
    fn show_ctrl_c_prompt(&self) -> bool {
        if let Some(first_time) = self.ctrl_c_time {
            std::time::Instant::now().duration_since(first_time) < CTRL_C_TIMEOUT
        } else {
            false
        }
    }

    fn current_list_state(&mut self) -> &mut ListState {
        if self.in_advanced {
            &mut self.advanced_list_state
        } else {
            &mut self.main_list_state
        }
    }

    fn item_count(&self) -> usize {
        if self.in_advanced {
            7 // Advanced menu items
        } else {
            3 // Main menu items
        }
    }

    fn select_next(&mut self) {
        let count = self.item_count();
        let state = if self.in_advanced {
            &mut self.advanced_list_state
        } else {
            &mut self.main_list_state
        };
        let current = state.selected().unwrap_or(0);
        let next = (current + 1) % count;
        state.select(Some(next));
    }

    fn select_previous(&mut self) {
        let count = self.item_count();
        let state = if self.in_advanced {
            &mut self.advanced_list_state
        } else {
            &mut self.main_list_state
        };
        let current = state.selected().unwrap_or(0);
        let prev = (current + count - 1) % count;
        state.select(Some(prev));
    }

    fn get_selection(&self) -> Option<MenuSelection> {
        if self.in_advanced {
            match self.advanced_list_state.selected()? {
                0 => Some(MenuSelection::Wipe),
                1 => {
                    // Return first template or empty string (will show OS picker if templates available)
                    let template = self.boot_options.templates.first()
                        .map(|t| t.name.clone())
                        .unwrap_or_default();
                    Some(MenuSelection::InstallOs(template))
                }
                2 => {
                    // Return first ISO or empty string
                    let iso = self.boot_options.isos.first()
                        .map(|i| i.url.clone())
                        .unwrap_or_default();
                    Some(MenuSelection::BootIso(iso))
                }
                3 => Some(MenuSelection::BootRescue),
                4 => Some(MenuSelection::VendorDiagnostics),
                5 => Some(MenuSelection::RemoveFromDragonfly),
                6 => None, // Back
                _ => None,
            }
        } else {
            match self.main_list_state.selected()? {
                0 if self.existing_os.is_some() => Some(MenuSelection::BootExistingOs),
                1 => Some(MenuSelection::MemoryTest),
                2 => None, // Enter advanced menu
                _ => None,
            }
        }
    }
}

/// Display the boot menu and get user selection
pub async fn show_boot_menu(
    existing_os: Option<&DetectedOs>,
    server_url: Option<&str>,
) -> Result<MenuSelection> {
    // Fetch boot options from server
    let boot_options = fetch_boot_options(server_url).await;

    // Setup terminal
    terminal::enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = run_menu_loop(
        &mut terminal,
        existing_os.cloned(),
        boot_options,
    );

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Run the interactive menu loop
fn run_menu_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    existing_os: Option<DetectedOs>,
    boot_options: BootOptions,
) -> Result<MenuSelection> {
    use crossterm::event::KeyModifiers;

    let mut state = MenuState::new(existing_os, boot_options);

    loop {
        terminal.draw(|frame| draw_menu(frame, &mut state))?;

        // Poll for events
        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(KeyEvent { code, modifiers, kind: KeyEventKind::Press, .. }) = event::read()? {
                // Handle Ctrl-C (double-tap to exit)
                if code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL) {
                    if state.handle_ctrl_c() {
                        return Ok(MenuSelection::ExitToShell);
                    }
                    continue;
                }

                // Any other key clears the Ctrl-C pending state
                state.ctrl_c_pending = false;
                state.ctrl_c_time = None;

                match code {
                    KeyCode::Up | KeyCode::Char('k') => state.select_previous(),
                    KeyCode::Down | KeyCode::Char('j') => state.select_next(),
                    KeyCode::Enter | KeyCode::Char(' ') => {
                        if state.in_advanced {
                            if let Some(selection) = state.get_selection() {
                                return Ok(selection);
                            } else {
                                // Back selected
                                state.in_advanced = false;
                                state.main_list_state.select(Some(2));
                            }
                        } else {
                            match state.main_list_state.selected() {
                                Some(2) => {
                                    // Enter advanced menu
                                    state.in_advanced = true;
                                    state.advanced_list_state.select(Some(0));
                                }
                                _ => {
                                    if let Some(selection) = state.get_selection() {
                                        return Ok(selection);
                                    }
                                }
                            }
                        }
                    }
                    // 'q' exits to shell
                    KeyCode::Char('q') => {
                        return Ok(MenuSelection::ExitToShell);
                    }
                    // Esc goes back or boots existing OS
                    KeyCode::Esc => {
                        if state.in_advanced {
                            state.in_advanced = false;
                        } else if state.existing_os.is_some() {
                            return Ok(MenuSelection::BootExistingOs);
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

/// Draw the menu UI
fn draw_menu(frame: &mut Frame, state: &mut MenuState) {
    let area = frame.area();

    // Clear the screen
    frame.render_widget(Clear, area);

    // Calculate centered content area - adapts to any screen size
    // Use 90% width, 85% height, centered
    let content_area = center_rect(area, 90, 85);

    // Split content area vertically: logo, slogan, info, menu, footer
    let chunks = Layout::vertical([
        Constraint::Length(8),  // Logo (block text is ~7 lines)
        Constraint::Length(2),  // Slogan
        Constraint::Length(3),  // Info/status
        Constraint::Min(10),    // Menu
        Constraint::Length(3),  // Footer/help
    ])
    .split(content_area);

    // Draw logo
    draw_logo(frame, chunks[0]);

    // Draw slogan
    draw_slogan(frame, chunks[1]);

    // Draw info section
    draw_info(frame, chunks[2], &state.existing_os);

    // Draw menu
    if state.in_advanced {
        draw_advanced_menu(frame, chunks[3], state);
    } else {
        draw_main_menu(frame, chunks[3], state);
    }

    // Draw footer
    draw_footer(frame, chunks[4], state);
}

/// Center a rect within another rect using percentage of parent
fn center_rect(area: Rect, percent_x: u16, percent_y: u16) -> Rect {
    let popup_width = area.width * percent_x / 100;
    let popup_height = area.height * percent_y / 100;

    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;

    Rect::new(x, y, popup_width, popup_height)
}

/// Draw the dragonfly logo
fn draw_logo(frame: &mut Frame, area: Rect) {
    let logo = Paragraph::new(DRAGONFLY_LOGO)
        .style(Style::default().fg(Color::Cyan))
        .centered();
    frame.render_widget(logo, area);
}

/// Draw the slogan
fn draw_slogan(frame: &mut Frame, area: Rect) {
    let slogan = Paragraph::new(SLOGAN)
        .style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC))
        .centered();
    frame.render_widget(slogan, area);
}

/// Draw info/status section
fn draw_info(frame: &mut Frame, area: Rect, existing_os: &Option<DetectedOs>) {
    let info_text = if let Some(os) = existing_os {
        vec![
            Line::from(vec![
                Span::raw("Detected OS: "),
                Span::styled(&os.name, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled(&os.device, Style::default().fg(Color::DarkGray)),
            ]),
        ]
    } else {
        vec![
            Line::from(vec![
                Span::styled("No existing OS detected", Style::default().fg(Color::Yellow)),
            ]),
        ]
    };

    let info = Paragraph::new(info_text).centered();
    frame.render_widget(info, area);
}

/// Draw the main menu
fn draw_main_menu(frame: &mut Frame, area: Rect, state: &mut MenuState) {
    let has_os = state.existing_os.is_some();

    let items: Vec<ListItem> = vec![
        if has_os {
            ListItem::new(Line::from(vec![
                Span::raw("  Continue booting existing OS"),
            ]))
        } else {
            ListItem::new(Line::from(vec![
                Span::styled("  No OS to boot", Style::default().fg(Color::DarkGray)),
            ]))
        },
        ListItem::new("  Perform memory test"),
        ListItem::new(Line::from(vec![
            Span::raw("  Advanced options "),
            Span::styled("→", Style::default().fg(Color::DarkGray)),
        ])),
    ];

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Boot Menu ")
                .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan))
        )
        .highlight_style(
            Style::default()
                .bg(Color::Cyan)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD)
        )
        .highlight_symbol("▸ ");

    frame.render_stateful_widget(list, area, &mut state.main_list_state);
}

/// Draw the advanced menu
fn draw_advanced_menu(frame: &mut Frame, area: Rect, state: &mut MenuState) {
    // Build Install OS description
    let os_desc = if state.boot_options.templates.is_empty() {
        "No templates available".to_string()
    } else {
        format!("{} templates available", state.boot_options.templates.len())
    };

    // Build Boot ISO description
    let iso_desc = if state.boot_options.isos.is_empty() {
        "No ISOs available".to_string()
    } else {
        format!("{} ISOs available", state.boot_options.isos.len())
    };

    let items: Vec<ListItem> = vec![
        ListItem::new(Line::from(vec![
            Span::raw("  Wipe disk"),
            Span::styled("  Securely erase all data", Style::default().fg(Color::DarkGray)),
        ])),
        ListItem::new(Line::from(vec![
            Span::raw("  Install OS"),
            Span::styled(format!("  {}", os_desc), Style::default().fg(Color::DarkGray)),
        ])),
        ListItem::new(Line::from(vec![
            Span::raw("  Boot ISO"),
            Span::styled(format!("  {}", iso_desc), Style::default().fg(Color::DarkGray)),
        ])),
        ListItem::new(Line::from(vec![
            Span::raw("  Boot rescue environment"),
        ])),
        ListItem::new(Line::from(vec![
            Span::raw("  Vendor diagnostics"),
        ])),
        ListItem::new(Line::from(vec![
            Span::raw("  Remove from Dragonfly"),
        ])),
        ListItem::new(Line::from(vec![
            Span::styled("  ← Back", Style::default().fg(Color::DarkGray)),
        ])),
    ];

    let list = List::new(items)
        .block(
            Block::default()
                .title(" Advanced Options ")
                .title_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
        )
        .highlight_style(
            Style::default()
                .bg(Color::Yellow)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD)
        )
        .highlight_symbol("▸ ");

    frame.render_stateful_widget(list, area, &mut state.advanced_list_state);
}

/// Draw the footer with help text
fn draw_footer(frame: &mut Frame, area: Rect, state: &MenuState) {
    let help_text = if state.show_ctrl_c_prompt() {
        Line::from(vec![
            Span::styled("Press Ctrl-C again to exit to shell", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ])
    } else if state.in_advanced {
        Line::from(vec![
            Span::styled("↑↓", Style::default().fg(Color::Cyan)),
            Span::raw(" Navigate  "),
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::raw(" Select  "),
            Span::styled("Esc", Style::default().fg(Color::Cyan)),
            Span::raw(" Back  "),
            Span::styled("q", Style::default().fg(Color::Cyan)),
            Span::raw(" Exit"),
        ])
    } else {
        Line::from(vec![
            Span::styled("↑↓", Style::default().fg(Color::Cyan)),
            Span::raw(" Navigate  "),
            Span::styled("Enter", Style::default().fg(Color::Cyan)),
            Span::raw(" Select  "),
            Span::styled("Esc", Style::default().fg(Color::Cyan)),
            Span::raw(" Boot OS  "),
            Span::styled("q", Style::default().fg(Color::Cyan)),
            Span::raw(" Exit"),
        ])
    };

    let footer = Paragraph::new(help_text)
        .style(Style::default().fg(Color::DarkGray))
        .centered();
    frame.render_widget(footer, area);
}

/// Wait for check-in with user interrupt capability
///
/// Implements the "invisible PXE" philosophy:
/// - If there's an existing OS: quick timeout, boot it if server is slow
/// - If no existing OS: wait indefinitely for server (nothing else to do)
/// - User can always press ENTER/SPACEBAR to access the menu
///
/// Returns None if user wants the menu, Some(response) if we got a Dragonfly response.
pub async fn wait_for_checkin_with_interrupt<F, Fut>(
    check_in_fn: F,
    existing_os: Option<&DetectedOs>,
) -> Result<Option<CheckInResponse>>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<CheckInResponse>>,
{
    // Channel for keyboard events
    let (key_tx, mut key_rx) = mpsc::channel(1);

    // Spawn keyboard listener
    let key_handle = std::thread::spawn(move || {
        let _ = terminal::enable_raw_mode();
        loop {
            if event::poll(Duration::from_millis(50)).unwrap_or(false) {
                if let Ok(Event::Key(KeyEvent { code, kind: KeyEventKind::Press, .. })) = event::read() {
                    if matches!(code, KeyCode::Enter | KeyCode::Char(' ')) {
                        let _ = key_tx.blocking_send(());
                        break;
                    }
                }
            }
        }
        let _ = terminal::disable_raw_mode();
    });

    // Setup minimal terminal for splash
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    terminal::enable_raw_mode()?;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Draw splash screen
    terminal.draw(|frame| draw_splash(frame, existing_os))?;

    // Behavior depends on whether we have an existing OS:
    // - Has OS: quick timeout, boot it if server is slow/dead
    // - No OS: wait indefinitely for server (we have nothing else to do)
    let result = if existing_os.is_some() {
        // We have an existing OS - use quick timeout
        tokio::select! {
            // User pressed a key
            _ = key_rx.recv() => {
                drop(key_handle);
                info!("User interrupted - showing boot menu");
                Ok(None)
            }

            // Check-in with timeout (3s gives user time to react)
            result = tokio::time::timeout(DRAGONFLY_TIMEOUT, check_in_fn()) => {
                drop(key_rx);

                match result {
                    Ok(Ok(response)) => {
                        debug!(action = ?response.action, "Got Dragonfly response");
                        Ok(Some(response))
                    }
                    Ok(Err(e)) => {
                        // Server error - boot existing OS
                        warn!(error = %e, "Check-in failed, booting existing OS");
                        Ok(Some(CheckInResponse {
                            machine_id: String::new(),
                            memorable_name: String::new(),
                            is_new: false,
                            action: AgentAction::LocalBoot,
                            workflow_id: None,
                        }))
                    }
                    Err(_) => {
                        // Timeout - boot existing OS (invisible to user)
                        info!("Server unreachable, booting existing OS");
                        Ok(Some(CheckInResponse {
                            machine_id: String::new(),
                            memorable_name: String::new(),
                            is_new: false,
                            action: AgentAction::LocalBoot,
                            workflow_id: None,
                        }))
                    }
                }
            }
        }
    } else {
        // No existing OS - wait indefinitely for server (or user interrupt)
        tokio::select! {
            // User pressed a key
            _ = key_rx.recv() => {
                drop(key_handle);
                info!("User interrupted - showing boot menu");
                Ok(None)
            }

            // Check-in with no timeout
            result = check_in_fn() => {
                drop(key_rx);

                match result {
                    Ok(response) => {
                        debug!(action = ?response.action, "Got Dragonfly response");
                        Ok(Some(response))
                    }
                    Err(e) => {
                        // Server error - show menu (nothing else to do)
                        warn!(error = %e, "Check-in failed, showing boot menu");
                        Ok(None)
                    }
                }
            }
        }
    };

    // Restore terminal
    terminal::disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;

    result
}

/// Draw the splash screen during boot
fn draw_splash(frame: &mut Frame, existing_os: Option<&DetectedOs>) {
    let area = frame.area();
    frame.render_widget(Clear, area);

    let content_area = center_rect(area, 90, 70);

    let chunks = Layout::vertical([
        Constraint::Length(8),  // Logo
        Constraint::Length(2),  // Slogan
        Constraint::Length(4),  // Status
        Constraint::Length(3),  // Prompt
    ])
    .split(content_area);

    // Logo
    let logo = Paragraph::new(DRAGONFLY_LOGO)
        .style(Style::default().fg(Color::Cyan))
        .centered();
    frame.render_widget(logo, chunks[0]);

    // Slogan
    let slogan = Paragraph::new(SLOGAN)
        .style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC))
        .centered();
    frame.render_widget(slogan, chunks[1]);

    // Status
    let status_lines = if let Some(os) = existing_os {
        vec![
            Line::from(""),
            Line::from(vec![
                Span::raw("Detected: "),
                Span::styled(&os.name, Style::default().fg(Color::Green)),
            ]),
            Line::from(""),
            Line::from(Span::styled("Contacting Dragonfly...", Style::default().fg(Color::DarkGray))),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled("No existing OS detected", Style::default().fg(Color::Yellow))),
            Line::from(""),
            Line::from(Span::styled("Contacting Dragonfly...", Style::default().fg(Color::DarkGray))),
        ]
    };
    let status = Paragraph::new(status_lines).centered();
    frame.render_widget(status, chunks[2]);

    // Prompt
    let prompt = Paragraph::new(Line::from(vec![
        Span::raw("Press "),
        Span::styled("ENTER", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" or "),
        Span::styled("SPACE", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" for boot menu"),
    ]))
    .centered();
    frame.render_widget(prompt, chunks[3]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_menu_selection_variants() {
        let sel = MenuSelection::BootExistingOs;
        assert_eq!(sel, MenuSelection::BootExistingOs);

        let sel = MenuSelection::InstallOs("debian-13".to_string());
        if let MenuSelection::InstallOs(template) = sel {
            assert_eq!(template, "debian-13");
        } else {
            panic!("Expected InstallOs variant");
        }
    }

    #[test]
    fn test_center_rect() {
        let area = Rect::new(0, 0, 100, 50);
        let centered = center_rect(area, 50, 50);

        assert_eq!(centered.width, 50);
        assert_eq!(centered.height, 25);
        assert_eq!(centered.x, 25);
        assert_eq!(centered.y, 12);
    }

    #[test]
    fn test_menu_state_navigation() {
        let mut state = MenuState::new(None, BootOptions::default());

        assert_eq!(state.main_list_state.selected(), Some(0));

        state.select_next();
        assert_eq!(state.main_list_state.selected(), Some(1));

        state.select_next();
        assert_eq!(state.main_list_state.selected(), Some(2));

        state.select_next();
        assert_eq!(state.main_list_state.selected(), Some(0)); // Wraps

        state.select_previous();
        assert_eq!(state.main_list_state.selected(), Some(2)); // Wraps back
    }
}
