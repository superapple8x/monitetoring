use std::collections::HashSet;
use ratatui::{
    widgets::{Chart, Dataset, Axis, GraphType},
    style::{Style, Color},
    text::Span,
    Frame,
};
use crate::types::{App, ChartType, MetricsMode};
use crate::ui::utils::format_bytes;

/// Render charts in the given area
pub fn render_charts(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (datasets, y_max, chart_title) = match app.chart_type {
        ChartType::ProcessLines => {
            // Line chart for individual process (existing logic)
            if let Some(pid) = app.selected_process {
                if let Some(process_info) = app.stats.get(&pid) {
                    let mut max_val = 0f64;
                    for &(_, v) in process_info.sent_history.iter().chain(process_info.received_history.iter()) {
                        if v > max_val {
                            max_val = v;
                        }
                    }
                    let y_max = if max_val < 1f64 { 1f64 } else { max_val * 1.2 };
                    let datasets = vec![
                        Dataset::default()
                            .name("Sent")
                            .marker(ratatui::symbols::Marker::Braille)
                            .style(Style::default().fg(Color::Cyan))
                            .graph_type(GraphType::Line)
                            .data(&process_info.sent_history),
                        Dataset::default()
                            .name("Received")
                            .marker(ratatui::symbols::Marker::Braille)
                            .style(Style::default().fg(Color::Magenta))
                            .graph_type(GraphType::Line)
                            .data(&process_info.received_history),
                    ];
                    (datasets, y_max, format!("Process {} Bandwidth (last 5 min)", pid))
                } else {
                    (Vec::new(), 1f64, "Process Bandwidth (last 5 min)".to_string())
                }
            } else {
                (Vec::new(), 1f64, "Process Bandwidth (last 5 min)".to_string())
            }
        },
        ChartType::SystemStacked => {
            // Stacked area chart for system-wide bandwidth
            if app.chart_datasets.is_empty() {
                (Vec::new(), 1f64, "System Bandwidth Stack (last 5 min)".to_string())
            } else {
                // Use pre-built datasets from app
                let datasets: Vec<Dataset> = app.chart_datasets.iter()
                    .map(|(name, data, color)| {
                        Dataset::default()
                            .name(name.clone())
                            .marker(ratatui::symbols::Marker::Braille)
                            .style(Style::default().fg(*color))
                            .graph_type(GraphType::Line)
                            .data(data)
                    })
                    .collect();

                let max_stack = app.chart_datasets.iter()
                    .flat_map(|(_, data, _)| data.iter().map(|(_, y)| *y))
                    .fold(1f64, |acc, val| if val > acc { val } else { acc });

                let y_max = max_stack * 1.2;
                let metrics_label = match app.metrics_mode {
                    MetricsMode::Combined => "Combined (Send + Receive)",
                    MetricsMode::SendOnly => "Send Only", 
                    MetricsMode::ReceiveOnly => "Receive Only",
                };
                (datasets, y_max, format!("System Bandwidth Stack - {} (top 5)", metrics_label))
            }
        },
    };

    let now = app.start_time.elapsed().as_secs_f64();
    let x_min = if now > 300.0 { now - 300.0 } else { 0.0 };
    let x_axis = Axis::default()
        .title("Time (s)")
        .style(Style::default().fg(Color::Gray))
        .bounds([x_min, now]);

    // Helper to format rate nicely for axis labels
    let format_rate = |rate: f64| -> String {
        format!("{}/s", format_bytes(rate as u64))
    };

    // Build 5 evenly spaced labels for Y axis (0, 25%, 50%, 75%, 100%)
    let y_labels: Vec<Span> = (0..=4)
        .map(|i| {
            let val = y_max * i as f64 / 4.0;
            Span::raw(format_rate(val))
        })
        .collect();

    let y_axis = Axis::default()
        .title("Bandwidth")
        .style(Style::default().fg(Color::Gray))
        .labels(y_labels)
        .bounds([0.0, y_max]);

    let chart = Chart::new(datasets)
        .block(
            ratatui::widgets::Block::default()
                .title(chart_title)
                .borders(ratatui::widgets::Borders::ALL),
        )
        .x_axis(x_axis)
        .y_axis(y_axis);

    f.render_widget(chart, area);
}

/// Update chart datasets for system stacked chart
pub fn update_chart_datasets(app: &mut App) {
    if app.chart_type == ChartType::SystemStacked && !app.system_bandwidth_history.is_empty() {
        // Get top 5 processes by recent activity for readability
        let mut top_processes: Vec<(i32, u64)> = app.stats.iter()
            .map(|(pid, info)| (*pid, info.sent_rate + info.received_rate))
            .collect();
        top_processes.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        let top_pids: Vec<i32> = top_processes.into_iter().take(5).map(|(pid, _)| pid).collect();

        // Available colors for assignment
        let available_colors = [
            Color::Red, Color::Green, Color::Blue, Color::Yellow, Color::Magenta,
            Color::Cyan, Color::LightRed, Color::LightGreen, Color::LightBlue, Color::LightYellow,
            Color::LightMagenta, Color::LightCyan, Color::DarkGray, Color::Gray, Color::White
        ];
        
        let mut new_datasets = Vec::new();

        for &pid in &top_pids {
            let process_name = app.stats.get(&pid)
                .map(|info| info.name.clone())
                .unwrap_or_else(|| format!("PID {}", pid));

            // Get or assign a persistent color for this process
            let process_color = if let Some(&existing_color) = app.process_colors.get(&process_name) {
                existing_color
            } else {
                // Find a color that's not already in use, or cycle through if all are used
                let used_colors: HashSet<Color> = app.process_colors.values().cloned().collect();
                let new_color = available_colors.iter()
                    .find(|&&color| !used_colors.contains(&color))
                    .copied()
                    .unwrap_or(available_colors[app.process_colors.len() % available_colors.len()]);
                
                app.process_colors.insert(process_name.clone(), new_color);
                new_color
            };

            let process_data: Vec<(f64, f64)> = app.system_bandwidth_history.iter()
                .map(|(timestamp, snapshot)| {
                    let rate = snapshot.iter()
                        .find(|(p, _, _)| *p == pid)
                        .map(|(_, sent, recv)| {
                            match app.metrics_mode {
                                MetricsMode::Combined => sent + recv,
                                MetricsMode::SendOnly => *sent,
                                MetricsMode::ReceiveOnly => *recv,
                            }
                        })
                        .unwrap_or(0.0);
                    (*timestamp, rate)
                })
                .collect();

            if !process_data.is_empty() {
                new_datasets.push((process_name, process_data, process_color));
            }
        }
        
        app.chart_datasets = new_datasets;
    } else {
        app.chart_datasets.clear();
    }
} 