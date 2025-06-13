use std::io::{self, Write};
use pcap::Device;
use crate::config::{SavedConfig, load_config, save_config};

#[derive(Debug)]
pub enum InteractiveError {
    Io(io::Error),
    UserCancelled,
    NoInterfacesFound,
    PermissionDenied,
}

impl From<io::Error> for InteractiveError {
    fn from(error: io::Error) -> Self {
        InteractiveError::Io(error)
    }
}

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
}

impl NetworkInterface {
    fn from_device(device: Device) -> Self {
        Self {
            name: device.name,
            description: device.desc,
            is_up: device.flags.is_up(),
        }
    }

    fn display_line(&self, index: usize) -> String {
        let status = if self.is_up { "🟢" } else { "🔴" };
        let desc = self.description.as_deref().unwrap_or("No description");
        format!("   {}. {} {} - {}", index + 1, status, self.name, desc)
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
    // Auto-use saved configuration for faster startup
    println!("🎯 Using Saved Configuration");
    println!("   📡 Interface: {}", saved.interface);
    println!("   📊 Mode: {}", if saved.json_mode { "JSON output" } else { "Interactive TUI" });
    println!("   🐳 Container awareness: {}", if saved.containers_mode { "Enabled" } else { "Disabled" });
    println!("🚀 Starting monitoring...");
    println!();
    
    Ok(Some(InteractiveConfig {
        interface: saved.interface,
        json_mode: saved.json_mode,
        containers_mode: saved.containers_mode,
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
        
        let devices = match Device::list() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("❌ Error listing network devices: {}", e);
                eprintln!("   This might be due to insufficient permissions.");
                eprintln!("   Try running with sudo or check your network permissions.");
                return Ok(None);
            }
        };

        if devices.is_empty() {
            eprintln!("❌ No network interfaces found.");
            eprintln!("   Please check your network configuration.");
            return Ok(None);
        }

        let interfaces: Vec<NetworkInterface> = devices
            .into_iter()
            .map(NetworkInterface::from_device)
            .collect();

        // Display interfaces with enhanced information
        for (i, interface) in interfaces.iter().enumerate() {
            println!("{}", interface.display_line(i));
        }
        
        println!("   0. Quit");
        println!();
        println!("🟢 = Interface is up   🔴 = Interface is down");
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
        
        let json_mode = match InputHandler::numeric_choice_prompt("📊 Select mode (1-2)", 1, 2)? {
            Some(1) => false,
            Some(2) => true,
            _ => {
                println!("❌ Invalid selection. Please choose 1 or 2.");
                println!();
                continue;
            }
        };

        // Ask about container awareness
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