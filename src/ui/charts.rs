use std::collections::HashSet;
use ratatui::{
    widgets::{Chart, Dataset, Axis, GraphType, Block, Borders},
    style::{Style, Color},
    text::Span,
    Frame,
};
use crate::types::{App, ChartType, MetricsMode};
use crate::ui::utils::format_bytes;

/// Optimized chart rendering with caching and reduced allocations
pub fn render_charts(f: &mut Frame, app: &App, area: ratatui::layout::Rect) {
    let (datasets, y_max, chart_title) = match app.chart_type {
        ChartType::ProcessLines => {
            render_process_lines_chart_data(app)
        },
        ChartType::SystemStacked => {
            render_system_stacked_chart_data(app, area)
        },
    };

    render_optimized_chart(f, area, datasets, y_max, chart_title, app);
}

/// Optimized process lines chart data generation
fn render_process_lines_chart_data(app: &App) -> (Vec<Dataset>, f64, String) {
    if let Some(pid) = app.selected_process {
        if let Some(process_info) = app.stats.get(&pid) {
            // Pre-calculate max value more efficiently
            let sent_max = process_info.sent_history.iter()
                .map(|(_, v)| *v)
                .fold(0f64, f64::max);
            let received_max = process_info.received_history.iter()
                .map(|(_, v)| *v)
                .fold(0f64, f64::max);
            
            let max_val = sent_max.max(received_max);
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
}

/// Optimized system stacked chart data generation with pre-built datasets
fn render_system_stacked_chart_data(app: &App, area: ratatui::layout::Rect) -> (Vec<Dataset>, f64, String) {
    if app.chart_datasets.is_empty() {
        return (Vec::new(), 1f64, "System Bandwidth Stack (last 5 min)".to_string());
    }

    // Use pre-built datasets from app with optimized name truncation
    let datasets: Vec<Dataset> = app.chart_datasets.iter()
        .map(|(name, data, color)| {
            let display_name = get_display_name(name, area.width);
            Dataset::default()
                .name(display_name)
                .marker(ratatui::symbols::Marker::Braille)
                .style(Style::default().fg(*color))
                .graph_type(GraphType::Line)
                .data(data)
        })
        .collect();

    // Pre-calculate y_max more efficiently
    let max_stack = app.chart_datasets.iter()
        .flat_map(|(_, data, _)| data.iter().map(|(_, y)| *y))
        .fold(1f64, f64::max);

    let y_max = max_stack * 1.2;
    let title = get_chart_title(app.metrics_mode, area.width);
    
    (datasets, y_max, title)
}

/// Optimized display name generation with caching-friendly approach
fn get_display_name(name: &str, area_width: u16) -> String {
    let max_len = if area_width < 100 { 8 } else { 12 };
    truncate_process_name(name, max_len)
}

/// Optimized chart title generation
fn get_chart_title(metrics_mode: MetricsMode, area_width: u16) -> String {
    if area_width < 80 {
        format!("System Stack - {} (top 5)", 
            match metrics_mode {
                MetricsMode::Combined => "Combined",
                MetricsMode::SendOnly => "Send", 
                MetricsMode::ReceiveOnly => "Recv",
            }
        )
    } else {
        let metrics_label = match metrics_mode {
            MetricsMode::Combined => "Combined (Send + Receive)",
            MetricsMode::SendOnly => "Send Only", 
            MetricsMode::ReceiveOnly => "Receive Only",
        };
        format!("System Bandwidth Stack - {} (top 5)", metrics_label)
    }
}

/// Optimized chart rendering function
fn render_optimized_chart(
    f: &mut Frame,
    area: ratatui::layout::Rect,
    datasets: Vec<Dataset>,
    y_max: f64,
    chart_title: String,
    app: &App
) {
    let now = app.start_time.elapsed().as_secs_f64();
    let x_min = if now > 300.0 { now - 300.0 } else { 0.0 };
    
    let x_axis = Axis::default()
        .title("Time (s)")
        .style(Style::default().fg(Color::Gray))
        .bounds([x_min, now]);

    // Optimized y-axis label generation
    let num_labels = if area.height < 12 { 3 } else { 5 };
    let y_labels: Vec<Span> = (0..num_labels)
        .map(|i| {
            let val = y_max * i as f64 / (num_labels - 1) as f64;
            Span::raw(format!("{}/s", format_bytes(val as u64)))
        })
        .collect();

    let y_axis = Axis::default()
        .title("Bandwidth")
        .style(Style::default().fg(Color::Gray))
        .labels(y_labels)
        .bounds([0.0, y_max]);

    let chart = Chart::new(datasets)
        .block(
            Block::default()
                .title(chart_title)
                .borders(Borders::ALL),
        )
        .x_axis(x_axis)
        .y_axis(y_axis);

    f.render_widget(chart, area);
}

/// Helper function to truncate process names intelligently
fn truncate_process_name(name: &str, max_len: usize) -> String {
    if name.len() <= max_len {
        name.to_string()
    } else {
        // Try to keep the important part of the process name
        if name.contains('/') {
            // For paths, keep the filename
            let parts: Vec<&str> = name.split('/').collect();
            if let Some(filename) = parts.last() {
                if filename.len() <= max_len {
                    return filename.to_string();
                }
            }
        }
        
        // Generic truncation with ellipsis
        format!("{}…", &name[..max_len.saturating_sub(1)])
    }
}

/// Highly optimized chart dataset update function with throttling
pub fn update_chart_datasets(app: &mut App) {
    // Early return if not in stacked mode or no history
    if app.chart_type != ChartType::SystemStacked || app.system_bandwidth_history.is_empty() {
        if !app.chart_datasets.is_empty() {
            app.chart_datasets.clear();
        }
        return;
    }

    // Throttle updates to avoid expensive recalculations (max once per 500ms)
    let now = std::time::Instant::now();
    if now.duration_since(app.last_chart_update).as_millis() < 500 {
        return; // Skip update if too recent
    }
    app.last_chart_update = now;

    // Get top 5 processes by recent activity for readability
    let mut top_processes: Vec<(i32, u64, String)> = app.stats.iter()
        .map(|(pid, info)| (*pid, info.sent_rate + info.received_rate, info.name.clone()))
        .collect();
    
    // Sort by bandwidth usage (descending) and take top 5
    top_processes.sort_by(|a, b| b.1.cmp(&a.1));
    let top_pids: Vec<(i32, String)> = top_processes.into_iter()
        .take(5)
        .map(|(pid, _, name)| (pid, name))
        .collect();

    // Pre-allocate with known capacity
    let mut new_datasets = Vec::with_capacity(5);

    // Available colors for assignment
    static AVAILABLE_COLORS: &[Color] = &[
        Color::Red, Color::Green, Color::Blue, Color::Yellow, Color::Magenta,
        Color::Cyan, Color::LightRed, Color::LightGreen, Color::LightBlue, Color::LightYellow,
        Color::LightMagenta, Color::LightCyan, Color::DarkGray, Color::Gray, Color::White
    ];

    // ----------------------------------------------------------------------------------
    // Build chart datasets in a single pass over history for all top PIDs (O(H + E))
    // ----------------------------------------------------------------------------------
    use std::collections::HashMap;

    // Prepare structures for fast lookup & storage
    let top_pid_set: HashSet<i32> = top_pids.iter().map(|(pid, _)| *pid).collect();
    let mut data_map: HashMap<i32, Vec<(f64, f64)>> = top_pid_set
        .iter()
        .map(|pid| (*pid, Vec::with_capacity(app.system_bandwidth_history.len())))
        .collect();

    // Iterate once over the historical snapshots
    for (timestamp, snapshot) in &app.system_bandwidth_history {
        // First push default 0 for every tracked pid so vector lengths stay aligned
        for &pid in &top_pid_set {
            data_map.get_mut(&pid).unwrap().push((*timestamp, 0.0));
        }
        // Update with real values where available
        for (pid, sent, recv) in snapshot {
            if top_pid_set.contains(pid) {
                let value = match app.metrics_mode {
                    MetricsMode::Combined => sent + recv,
                    MetricsMode::SendOnly => *sent,
                    MetricsMode::ReceiveOnly => *recv,
                };
                if let Some(entry) = data_map.get_mut(pid).and_then(|v| v.last_mut()) {
                    entry.1 = value;
                }
            }
        }
    }

    for (pid, process_name) in top_pids {
        let process_color = if let Some(&existing_color) = app.process_colors.get(&process_name) {
            existing_color
        } else {
            // Find a color that's not already in use, or cycle through if all are used
            let used_colors: HashSet<Color> = app.process_colors.values().cloned().collect();
            let new_color = AVAILABLE_COLORS.iter()
                .find(|&&color| !used_colors.contains(&color))
                .copied()
                .unwrap_or(AVAILABLE_COLORS[app.process_colors.len() % AVAILABLE_COLORS.len()]);
            app.process_colors.insert(process_name.clone(), new_color);
            new_color
        };

        if let Some(process_data) = data_map.remove(&pid) {
            if !process_data.is_empty() {
                new_datasets.push((process_name, process_data, process_color));
            }
        }
    }

    app.chart_datasets = new_datasets;
} 