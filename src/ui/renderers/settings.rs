use ratatui::{
    widgets::{Block, Borders, Paragraph},
    layout::{Layout, Constraint, Direction, Alignment},
    style::{Style, Color, Modifier},
    text::{Line, Span},
    Frame
};
use crate::types::App;
use crate::config::load_config;

/// Render the settings mode for configuration management
pub fn render(f: &mut Frame, app: &App) {
    // Main layout: Title + Settings Content + Notification (if any)
    let main_chunks = if app.settings_notification.is_some() {
        Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Title header
                Constraint::Min(0),     // Settings content
                Constraint::Length(3),  // Notification
            ])
            .split(f.size())
    } else {
        Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Title header
                Constraint::Min(0),     // Settings content
            ])
            .split(f.size())
    };

    render_title(f, main_chunks[0]);
    render_settings_content(f, app, main_chunks[1]);
    
    // Render notification if present
    if app.settings_notification.is_some() && main_chunks.len() > 2 {
        render_notification(f, app, main_chunks[2]);
    }
}

/// Render the title header
fn render_title(f: &mut Frame, area: ratatui::layout::Rect) {
    let block = Block::default().title("Settings & Configuration").borders(Borders::ALL);
    let inner = block.inner(area);
    f.render_widget(block, area);

    let nav_text = "q: quit | Tab: switch mode | r: remove config | Esc: back to main";
    let nav_paragraph = Paragraph::new(nav_text);
    f.render_widget(nav_paragraph, inner);
}

/// Render the main settings content
fn render_settings_content(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    // Split into configuration info and actions
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50), // Current configuration
            Constraint::Percentage(50), // Available actions
        ])
        .split(area);

    render_current_config(f, app, chunks[0]);
    render_available_actions(f, chunks[1]);
}

/// Render current configuration information
fn render_current_config(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let config_info = if let Some(config) = load_config() {
        let mut lines = vec![
            Line::from(vec![
                Span::styled("📡 Interface: ", Style::default().fg(Color::Cyan)),
                Span::raw(config.interface.clone()),
            ]),
            Line::from(vec![
                Span::styled("📊 Mode: ", Style::default().fg(Color::Cyan)),
                Span::raw(if config.json_mode { "JSON output" } else { "Interactive TUI" }),
            ]),
            Line::from(vec![
                Span::styled("🐳 Container awareness: ", Style::default().fg(Color::Cyan)),
                Span::raw(if config.containers_mode { "Enabled" } else { "Disabled" }),
            ]),
            Line::from(vec![
                Span::styled("📈 Show total columns: ", Style::default().fg(Color::Cyan)),
                Span::raw(if config.show_total_columns { "Yes" } else { "No" }),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("🔔 Active alerts: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{}", config.alerts.len())),
            ]),
            Line::from(""),
            Line::from("Highlighting thresholds:"),
        ];

        let large_packet_style = if app.settings_selected_option == 0 {
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(
            format!("  Large packet: {} bytes", config.large_packet_threshold),
            large_packet_style,
        )));

        let frequent_conn_style = if app.settings_selected_option == 1 {
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(
            format!("  Frequent connection: {} packets", config.frequent_connection_threshold),
            frequent_conn_style,
        )));

        lines
    } else {
        vec![
            Line::from(Span::styled(
                "No saved configuration found",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::ITALIC)
            )),
            Line::from(""),
            Line::from("Current session settings:"),
            Line::from(vec![
                Span::styled("🐳 Container awareness: ", Style::default().fg(Color::Cyan)),
                Span::raw(if app.containers_mode { "Enabled" } else { "Disabled" }),
            ]),
            Line::from(vec![
                Span::styled("📈 Show total columns: ", Style::default().fg(Color::Cyan)),
                Span::raw(if app.show_total_columns { "Yes" } else { "No" }),
            ]),
        ]
    };

    let config_widget = Paragraph::new(config_info)
        .block(Block::default().title("Current Configuration").borders(Borders::ALL))
        .alignment(Alignment::Left);
    f.render_widget(config_widget, area);
}

/// Render available actions
fn render_available_actions(f: &mut Frame, area: ratatui::layout::Rect) {
    let actions = vec![
        Line::from(vec![
            Span::styled("↑/↓", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(" - Navigate settings"),
        ]),
        Line::from(vec![
            Span::styled("←/→", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(" - Adjust selected setting"),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled("r", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(" - Remove saved configuration"),
        ]),
        Line::from("    Clears all saved settings and alerts"),
        Line::from("    Exit and restart to reconfigure"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Tab", Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
            Span::raw(" - Switch to other modes"),
        ]),
        Line::from("    Navigate between Main/Bandwidth/Overview/Settings"),
        Line::from(""),
        Line::from(vec![
            Span::styled("Tips:", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]),
        Line::from("• Configuration is auto-saved when you"),
        Line::from("  complete the guided setup"),
        Line::from("• Alerts persist between sessions"),
        Line::from("• Reset if you want to change interface"),
        Line::from("  or other core settings"),
    ];

    let actions_widget = Paragraph::new(actions)
        .block(Block::default().title("Available Actions").borders(Borders::ALL))
        .alignment(Alignment::Left);
    f.render_widget(actions_widget, area);
}

/// Render settings-specific notifications
fn render_notification(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    if let Some(msg) = &app.settings_notification {
        let style = if msg.starts_with("✅") {
            Style::default().fg(Color::Green)
        } else if msg.starts_with("❌") {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::Yellow)
        };
        
        let notification = Paragraph::new(msg.as_str())
            .style(style)
            .block(Block::default().borders(Borders::ALL).title("Status"));
        f.render_widget(notification, area);
    }
} 