/// Parse user input to bytes with unit support (KB, MB, GB, TB)
pub fn parse_input_to_bytes(input: &str) -> u64 {
    let input = input.trim().to_uppercase();
    let mut num_part = String::new();
    let mut unit_part = String::new();

    for c in input.chars() {
        if c.is_digit(10) || c == '.' {
            num_part.push(c);
        } else {
            unit_part.push(c);
        }
    }

    let num = num_part.parse::<f64>().unwrap_or(0.0);
    let unit = unit_part.trim();

    let multiplier = match unit {
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => 1.0,
    };

    (num * multiplier) as u64
}

/// Format bytes to human-readable string with appropriate units
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let bytes_f = bytes as f64;
    let unit_index = (bytes_f.log(THRESHOLD).floor() as usize).min(UNITS.len() - 1);
    let size = bytes_f / THRESHOLD.powi(unit_index as i32);
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
} 