use std::io::{self, Write};
use pcap::Device;
use crate::config::{SavedConfig, load_config, save_config};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::thread;
use std::sync::mpsc;
use crossterm::event::{self, Event, KeyCode};


pub struct InteractiveConfig {
    pub interface: String,
    pub json_mode: bool,
    pub containers_mode: bool,
    pub show_total_columns: bool,
}

/// Helper struct for managing user input operations
struct InputHandler;

impl InputHandler {
    /// Gets user input with automatic trimming
    fn get_input() -> Result<String, io::Error> {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }

    /// Prompts user with a question and handles yes/no responses
    fn confirm_prompt(message: &str, default_yes: bool) -> Result<bool, io::Error> {
        let default_text = if default_yes { "[Y/n]" } else { "[y/N]" };
        
        loop {
            print!("{} {}: ", message, default_text);
            io::stdout().flush()?;

            let input = Self::get_input()?.to_lowercase();
            
            match input.as_str() {
                "" => return Ok(default_yes),
                "y" | "yes" => return Ok(true),
                "n" | "no" => return Ok(false),
                _ => {
                    println!("❌ Please enter Y for yes or N for no.");
                    println!();
                }
            }
        }
    }

    /// Prompts user for a numeric choice within a range
    fn numeric_choice_prompt(prompt: &str, min: usize, max: usize) -> Result<Option<usize>, io::Error> {
        loop {
            print!("{}: ", prompt);
            io::stdout().flush()?;

            let input = Self::get_input()?;
            
            match input.parse::<usize>() {
                Ok(0) if min == 0 => return Ok(None), // Quit option
                Ok(n) if n >= min && n <= max => return Ok(Some(n)),
                _ => {
                    if min == 0 {
                        println!("❌ Invalid selection. Please enter a number between {} and {} (or 0 to quit).", min, max);
                    } else {
                        println!("❌ Invalid selection. Please enter a number between {} and {}.", min, max);
                    }
                    println!();
                }
            }
        }
    }

    /// Prompts user for a numeric choice with a default value when Enter is pressed
    fn numeric_choice_prompt_with_default(prompt: &str, min: usize, max: usize, default: usize) -> Result<Option<usize>, io::Error> {
        loop {
            print!("{} [{}]: ", prompt, default);
            io::stdout().flush()?;

            let input = Self::get_input()?;
            
            if input.is_empty() {
                // Return default when Enter is pressed without input
                return Ok(Some(default));
            }
            
            match input.parse::<usize>() {
                Ok(0) if min == 0 => return Ok(None), // Quit option
                Ok(n) if n >= min && n <= max => return Ok(Some(n)),
                _ => {
                    if min == 0 {
                        println!("❌ Invalid selection. Please enter a number between {} and {} (or 0 to quit), or press Enter for default ({}).", min, max, default);
                    } else {
                        println!("❌ Invalid selection. Please enter a number between {} and {}, or press Enter for default ({}).", min, max, default);
                    }
                    println!();
                }
            }
        }
    }
}

/// Helper struct for display formatting
struct DisplayHelper;

impl DisplayHelper {
    fn print_header(title: &str, width: usize) {
        println!("{}", title);
        println!("{}", "=".repeat(width));
        println!();
    }

    fn print_config_summary(interface: &str, json_mode: bool, containers_mode: bool, show_total_columns: bool) {
        println!("📋 Configuration Summary:");
        println!("   📡 Interface: {}", interface);
        println!("   📊 Mode: {}", if json_mode { "JSON output" } else { "Interactive TUI" });
        println!("   🐳 Container awareness: {}", if containers_mode { "Enabled" } else { "Disabled" });
        println!("   📈 Show total columns: {}", if show_total_columns { "Yes" } else { "No" });
        println!();
    }
}

/// Enhanced device information with validation
struct NetworkInterface {
    name: String,
    description: Option<String>,
    is_up: bool,
    traffic_bytes: u64,  // Total bytes observed during measurement period
}

impl NetworkInterface {
    fn from_device(device: Device) -> Self {
        Self {
            name: device.name,
            description: device.desc,
            is_up: device.flags.is_up(),
            traffic_bytes: 0,
        }
    }

    fn is_pseudo(&self) -> bool {
        matches!(self.name.as_str(), "any") ||
        self.name.starts_with("nfqueue") ||
        self.name.starts_with("usbmon")
    }

    fn display_line(&self, index: usize, is_recommended: bool) -> String {
        let status = if self.is_up { "🟢" } else { "🔴" };
        let desc = self.description.as_deref().unwrap_or("No description");
        let traffic_info = if self.traffic_bytes > 0 {
            format!(" [{}]", format_bytes(self.traffic_bytes))
        } else {
            String::new()
        };
        let recommended = if is_recommended { " (recommended)" } else { "" };
        format!("   {}. {} {}{}{} - {}", index + 1, status, self.name, traffic_info, recommended, desc)
    }

    fn measure_traffic(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        // Skip measurement for interfaces that are down
        if !self.is_up {
            return Ok(());
        }

        let device = match crate::dependencies::DependencyChecker::device_from_name_with_dependency_check(&self.name) {
            Ok(device) => device,
            Err(_) => return Ok(()), // Skip interfaces that can't be opened due to dependency issues
        };
        let cap = match crate::dependencies::DependencyChecker::capture_from_device_with_dependency_check(device) {
            Ok(cap) => cap,
            Err(_) => return Ok(()), // Skip interfaces that can't be opened due to dependency issues
        };
        let cap = cap.timeout(100)  // Short timeout for quick sampling
            .open();
        
        let mut cap = match cap {
            Ok(c) => c,
            Err(_) => return Ok(()), // Skip interfaces we can't open
        };

        let start_time = Instant::now();
        let mut total_bytes = 0u64;

        // Measure for exactly 5 seconds
        const MEASURE_DURATION_SECS: u64 = 5;
        while start_time.elapsed() < Duration::from_secs(MEASURE_DURATION_SECS) {
            match cap.next_packet() {
                Ok(packet) => {
                    total_bytes += packet.data.len() as u64;
                }
                Err(_) => {
                    // Timeout or error, continue sampling
                    thread::sleep(Duration::from_millis(10));
                }
            }
        }

        self.traffic_bytes = total_bytes;
        Ok(())
    }
}

// Helper function to format bytes (same as in ui/utils.rs)
fn format_bytes(bytes: u64) -> String {
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

pub fn run_interactive_mode() -> Result<Option<InteractiveConfig>, io::Error> {
    // Check if we have a saved configuration
    if let Some(saved) = load_config() {
        return handle_existing_config(saved);
    }

    // No saved config, run full interactive setup
    run_full_interactive_setup()
}

fn handle_existing_config(saved: SavedConfig) -> Result<Option<InteractiveConfig>, io::Error> {
    // Windows build: force container awareness off regardless of saved setting
    let containers_mode_effective = if cfg!(windows) { false } else { saved.containers_mode };

    // Auto-use saved configuration for faster startup
    println!("🎯 Using Saved Configuration");
    println!("   📡 Interface: {}", saved.interface);
    println!("   📊 Mode: {}", if saved.json_mode { "JSON output" } else { "Interactive TUI" });
    println!("   🐳 Container awareness: {}", if containers_mode_effective { "Enabled" } else { "Disabled" });
    println!("🚀 Starting monitoring...");
    println!();
    
    Ok(Some(InteractiveConfig {
        interface: saved.interface,
        json_mode: saved.json_mode,
        containers_mode: containers_mode_effective,
        show_total_columns: saved.show_total_columns,
    }))
}

fn run_full_interactive_setup() -> Result<Option<InteractiveConfig>, io::Error> {
    DisplayHelper::print_header("🚀 Welcome to Monitetoring - Interactive Setup", 50);

    // Step 1: Choose interface
    let interface = choose_interface()?;
    if interface.is_none() {
        return Ok(None); // User chose to quit
    }
    let interface = interface.unwrap();

    // Step 2: Choose mode
    let (json_mode, containers_mode) = choose_mode()?;

    // Step 3: Choose display options
    let show_total_columns = choose_display_options()?;

    // Step 4: Show summary and confirm
    println!();
    DisplayHelper::print_config_summary(&interface, json_mode, containers_mode, show_total_columns);

    // Step 4: Ask if user wants to save these settings
    let save_settings = ask_save_settings()?;

    // Step 5: Final confirmation
    if !InputHandler::confirm_prompt("🔥 Start monitoring with these settings?", true)? {
        println!("❌ Monitoring cancelled.");
        return Ok(None);
    }

    // Save configuration if user requested it
    if save_settings {
        save_user_config(&interface, json_mode, containers_mode, show_total_columns)?;
    }

    Ok(Some(InteractiveConfig {
        interface,
        json_mode,
        containers_mode,
        show_total_columns,
    }))
}

fn save_user_config(interface: &str, json_mode: bool, containers_mode: bool, show_total_columns: bool) -> Result<(), io::Error> {
    let config = SavedConfig {
        interface: interface.to_string(),
        json_mode,
        containers_mode,
        show_total_columns,
        alerts: vec![], // Initialize with no alerts
        large_packet_threshold: 100_000,
        frequent_connection_threshold: 20,
        setup_offered: false, // Will be set to true when we offer automatic setup
    };
    
    match save_config(&config) {
        Ok(_) => {
            println!("💾 Configuration saved! Next time you can start quickly.");
            println!();
        }
        Err(e) => {
            eprintln!("⚠️  Warning: Could not save configuration: {}", e);
            eprintln!("    (This won't affect monitoring, continuing...)");
            println!();
        }
    }
    
    Ok(())
}

fn ask_save_settings() -> Result<bool, io::Error> {
    println!("💾 Save these settings for future use?");
    println!("   (Next time you run the program, you can use these settings quickly)");
    println!();
    
    InputHandler::confirm_prompt("💾 Save settings?", true)
}

fn choose_interface() -> Result<Option<String>, io::Error> {
    loop {
        println!("🔌 Available Network Interfaces:");
        
        let devices = match crate::dependencies::DependencyChecker::list_devices_with_dependency_check() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("{}", e);
                return Ok(None);
            }
        };

        if devices.is_empty() {
            eprintln!("❌ No network interfaces found.");
            eprintln!("   Please check your network configuration.");
            return Ok(None);
        }

        let mut interfaces: Vec<NetworkInterface> = devices
            .into_iter()
            .map(NetworkInterface::from_device)
            .collect();

        // ===== TRAFFIC MEASUREMENT SECTION =====
        // CRITICAL: This section measures network traffic on interfaces to help users
        // identify the busiest interface. The implementation is carefully designed to:
        // 1. Never block longer than MEASURE_DURATION_SECS + OPEN_GRACE_SECS (6s total)
        // 2. Allow users to skip measurement with 'S' key
        // 3. Handle slow interface opens that can take 100-500ms each on Linux
        //
        // DEVELOPER WARNING: Modifying this section can cause:
        // - Interactive mode hanging for >10s when no traffic present
        // - Traffic measurements returning zero due to timing issues
        // - User interface becoming unresponsive
        //
        // Key timing considerations:
        // - Each worker thread does: open interface (~100-500ms) + measure for 5s + send result
        // - Main thread waits maximum 6s total (5s measurement + 1s grace for opens)
        // - If interface opens are slow, results may arrive after main thread timeout
        // - OPEN_GRACE_SECS compensates for typical interface open delays
        
        const MEASURE_DURATION_SECS: u64 = 5;
        const OPEN_GRACE_SECS: u64 = 1; // Extra time for slow interface opens on Linux
        let deadline = Instant::now() + Duration::from_secs(MEASURE_DURATION_SECS + OPEN_GRACE_SECS);
        println!(
            "📊 Measuring traffic on interfaces for {} seconds…",
            MEASURE_DURATION_SECS
        );
        println!("   (Press [S] to skip and continue immediately)");
        println!("   (This helps identify the busiest interface)");
        println!();
        
        // Spawn worker threads to measure each interface concurrently
        // Each thread: opens interface → samples for MEASURE_DURATION_SECS → sends result
        let (tx, rx) = mpsc::channel();
        for interface in &mut interfaces {
            if interface.is_up {
                let interface_name = interface.name.clone();
                let tx = tx.clone();
                thread::spawn(move || {
                    let mut temp_interface = NetworkInterface {
                        name: interface_name.clone(),
                        description: None,
                        is_up: true,
                        traffic_bytes: 0,
                    };
                    let _ = temp_interface.measure_traffic();
                    // Ignore send errors (main thread may timeout)
                    let _ = tx.send((interface_name, temp_interface.traffic_bytes));
                });
            }
        }

        drop(tx); // Close sending side in main thread

        // Collect results with hard deadline to prevent hanging
        // Main thread waits max 6s regardless of worker thread status
        let mut traffic_results: HashMap<String, u64> = HashMap::new();
        loop {
            // Allow user to skip measurement early with 's' key
            // This provides immediate escape if user doesn't want to wait
            if event::poll(Duration::from_millis(0)).unwrap_or(false) {
                if let Ok(Event::Key(k)) = event::read() {
                    if matches!(k.code, KeyCode::Char('s') | KeyCode::Char('S')) {
                        println!("⏭️  Skipping traffic measurement…");
                        break;
                    }
                }
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }

            match rx.recv_timeout(Duration::from_millis(50)) {
                Ok((name, bytes)) => {
                    traffic_results.insert(name, bytes);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    // Continue waiting until deadline or skip
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }
        }
        
        // Update interfaces with measured traffic
        for interface in &mut interfaces {
            if let Some(&traffic) = traffic_results.get(&interface.name) {
                interface.traffic_bytes = traffic;
            }
        }
        
        // Sort interfaces: real interfaces first, pseudo ("any"/"nfqueue"/"usbmon") last,
        // then by up/down status and finally by traffic bytes.
        interfaces.sort_by(|a, b| {
            use std::cmp::Ordering::*;
            match (a.is_pseudo(), b.is_pseudo()) {
                (false, true) => Less,
                (true, false) => Greater,
                _ => {
                    match (a.is_up, b.is_up) {
                        (true, false) => Less,
                        (false, true) => Greater,
                        _ => b.traffic_bytes.cmp(&a.traffic_bytes),
                    }
                }
            }
        });

        // Display interfaces with enhanced information
        for (i, interface) in interfaces.iter().enumerate() {
            let is_recommended = i == 0 && interface.is_up && interface.traffic_bytes > 0 && !interface.is_pseudo();
            println!("{}", interface.display_line(i, is_recommended));
        }
        
        println!("   0. Quit");
        println!();
        println!(
            "🟢 = Interface is up   🔴 = Interface is down   [traffic] = Bytes observed in {}s",
            MEASURE_DURATION_SECS
        );
        println!();
        
        match InputHandler::numeric_choice_prompt("📡 Select interface (number)", 0, interfaces.len())? {
            None => return Ok(None), // Quit
            Some(n) => {
                let selected_interface = &interfaces[n - 1];
                
                if !selected_interface.is_up {
                    println!("⚠️  Warning: Selected interface '{}' appears to be down.", selected_interface.name);
                    if !InputHandler::confirm_prompt("   Continue anyway?", false)? {
                        println!();
                        continue; // Go back to interface selection
                    }
                }
                
                return Ok(Some(selected_interface.name.clone()));
            }
        }
    }
}

fn choose_mode() -> Result<(bool, bool), io::Error> {
    loop {
        println!("📊 Choose Output Mode:");
        println!("   1. Interactive TUI (recommended) - Real-time monitoring interface");
        println!("   2. JSON output - Single 5-second capture for automation");
        println!();
        
        let json_mode = match InputHandler::numeric_choice_prompt_with_default("📊 Select mode (1-2)", 1, 2, 1)? {
            Some(1) => false,
            Some(2) => true,
            _ => {
                println!("❌ Invalid selection. Please choose 1 or 2.");
                println!();
                continue;
            }
        };

        // On Windows builds, skip the container awareness prompt entirely and disable the feature.
        if cfg!(windows) {
            println!();
            println!("🐳 Container awareness is not available on Windows and will be disabled.");
            println!();
            return Ok((json_mode, false));
        }

        // Ask about container awareness (Linux / macOS)
        println!();
        println!("🐳 Container Awareness:");
        println!("   This feature identifies and groups processes by container");
        println!("   (Docker, Podman, LXC, etc.)");
        println!();

        let containers_mode = InputHandler::confirm_prompt("🐳 Enable container awareness?", false)?;

        return Ok((json_mode, containers_mode));
    }
}

fn choose_display_options() -> Result<bool, io::Error> {
    println!();
    println!("📈 Display Options:");
    println!("   Show total bandwidth columns (Sent Total / Received Total) in process table?");
    println!("   These columns show cumulative data usage since monitoring started.");
    println!();
    
    InputHandler::confirm_prompt("📈 Show total columns?", false)
} 