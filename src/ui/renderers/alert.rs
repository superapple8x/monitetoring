use ratatui::{
    widgets::{Block, Borders, Paragraph},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
    text::{Line, Span, Text},
    Frame
};
use crate::types::{App, EditingField};

/// Render the alert editing mode view
pub fn render(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3), // Title
                Constraint::Length(3), // Threshold Input
                Constraint::Length(3), // Command Input
                Constraint::Min(0),    // Actions
            ]
            .as_ref(),
        )
        .split(f.size());

    render_title(f, app, chunks[0]);
    render_threshold_input(f, app, chunks[1]);
    render_command_input(f, app, chunks[2]);
    render_cursor(f, app, &chunks);
    render_actions(f, app, chunks[3]);
}

/// Render the title section
fn render_title(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let title_text = if let Some(pid) = app.selected_process {
        format!("Editing Alert for PID: {}", pid)
    } else {
        "Editing Alert".to_string()
    };
    let title = Paragraph::new(title_text)
        .block(Block::default().borders(Borders::ALL).title("Alert Editor (Esc to cancel, Enter to save)"));
    f.render_widget(title, area);
}

/// Render the threshold input field
fn render_threshold_input(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let threshold_input = Paragraph::new(app.alert_input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Threshold (e.g., 10MB, 2GB)")
        );
    f.render_widget(threshold_input, area);
}

/// Render the command input field
fn render_command_input(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let command_input = Paragraph::new(app.command_input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Command (leave empty to kill process)")
        );
    f.render_widget(command_input, area);
}

/// Set cursor position based on the currently editing field
fn render_cursor(f: &mut Frame, app: &App, chunks: &[ratatui::layout::Rect]) {
    match app.current_editing_field {
        EditingField::Threshold => {
            f.set_cursor(chunks[1].x + app.alert_input.len() as u16 + 1, chunks[1].y + 1);
        }
        EditingField::Command => {
            f.set_cursor(chunks[2].x + app.command_input.len() as u16 + 1, chunks[2].y + 1);
        }
    }
}

/// Render the action selection section
fn render_actions(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let actions = vec!["Kill Process", "Custom Command", "Alert"];
    let action_lines: Vec<Line> = actions
        .iter()
        .enumerate()
        .map(|(i, action)| {
            if i == app.selected_alert_action {
                Line::from(Span::styled(
                    format!("> {}", action),
                    Style::default().add_modifier(Modifier::BOLD).fg(Color::Cyan),
                ))
            } else {
                Line::from(format!("  {}", action))
            }
        })
        .collect();

    let actions_widget = Paragraph::new(Text::from(action_lines))
        .block(Block::default().borders(Borders::ALL).title("Action (use Tab to switch fields)"));
    f.render_widget(actions_widget, area);
} 