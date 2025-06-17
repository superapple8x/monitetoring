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

/// Highly optimized chart dataset update function with throttling and persistence
pub fn update_chart_datasets(app: &mut App) {
    if app.chart_type != ChartType::SystemStacked {
        if !app.chart_datasets.is_empty() {
            app.chart_datasets.clear();
        }
        return;
    }
    
    // Throttle updates to avoid expensive recalculations on every tick
    let now = std::time::Instant::now();
    if now.duration_since(app.last_chart_update).as_millis() < 500 {
        return;
    }
    app.last_chart_update = now;

    // Update process activity tracking
    let current_time = now;
    for (pid, info) in &app.stats {
        let total_rate = info.sent_rate + info.received_rate;
        if total_rate > 0 {
            app.process_last_active.insert(*pid, current_time);
        }
    }

    // Calculate 5-second average rates for more stable ranking
    let now_secs = app.start_time.elapsed().as_secs_f64();
    let calculate_avg_rate = |history: &[(f64, f64)]| -> u64 {
        let recent_samples: Vec<f64> = history.iter()
            .rev()
            .take_while(|(t, _)| now_secs - *t < 5.0)
            .map(|(_, v)| *v)
            .collect();
        
        if recent_samples.is_empty() {
            0
        } else {
            (recent_samples.iter().sum::<f64>() / recent_samples.len() as f64) as u64
        }
    };

    // Rank processes by 5-second average rate, but keep recently active processes visible
    let mut process_scores: Vec<_> = app.stats.iter()
        .map(|(pid, info)| {
            let avg_sent = calculate_avg_rate(&info.sent_history);
            let avg_received = calculate_avg_rate(&info.received_history);
            let avg_total = avg_sent + avg_received;
            
            // Boost score for recently active processes (within last 10 seconds)
            let boost = if let Some(last_active) = app.process_last_active.get(pid) {
                if current_time.duration_since(*last_active).as_secs() < 10 {
                    1000 // Add 1KB/s equivalent boost to keep recently active processes visible
                } else {
                    0
                }
            } else {
                0
            };
            
            (*pid, avg_total + boost)
        })
        .collect();

    process_scores.sort_by(|a, b| b.1.cmp(&a.1));
    
    let top_pids: HashSet<i32> = process_scores.into_iter()
        .take(5)
        .map(|(pid, _)| pid)
        .collect();

    let mut new_datasets = Vec::new();
    
    // Palette for assigning new colors to processes
    const COLORS: &[Color] = &[
        Color::Cyan, Color::Magenta, Color::Green, Color::Yellow, Color::Blue,
        Color::LightRed, Color::LightGreen, Color::LightBlue,
    ];

    for (pid, info) in &app.stats {
        if !top_pids.contains(pid) {
            continue;
        }

        let len = app.process_colors.len();
        let color = *app.process_colors.entry(*pid).or_insert_with(|| {
            COLORS[len % COLORS.len()]
        });
        
        let data = match app.metrics_mode {
            MetricsMode::Combined => {
                info.sent_history.iter().zip(&info.received_history)
                    .map(|((t, s), (_, r))| (*t, *s + *r))
                    .collect()
            },
            MetricsMode::SendOnly => info.sent_history.clone(),
            MetricsMode::ReceiveOnly => info.received_history.clone(),
        };

        new_datasets.push((info.name.clone(), data, color));
    }
    
    app.chart_datasets = new_datasets;
} 