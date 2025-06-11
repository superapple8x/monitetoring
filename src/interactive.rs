use std::io::{self, Write};
use pcap::Device;
use crate::config::Cli;

pub struct InteractiveConfig {
    pub interface: String,
    pub json_mode: bool,
    pub containers_mode: bool,
}

pub fn run_interactive_mode() -> Result<Option<InteractiveConfig>, io::Error> {
    println!("🚀 Welcome to Monitetoring - Interactive Setup");
    println!("{}", "=".repeat(50));
    println!();

    // Step 1: Choose interface
    let interface = choose_interface()?;
    if interface.is_none() {
        return Ok(None); // User chose to quit
    }
    let interface = interface.unwrap();

    // Step 2: Choose mode
    let (json_mode, containers_mode) = choose_mode()?;

    // Step 3: Show summary and confirm
    println!();
    println!("📋 Configuration Summary:");
    println!("   📡 Interface: {}", interface);
    println!("   📊 Mode: {}", if json_mode { "JSON output" } else { "Interactive TUI" });
    println!("   🐳 Container awareness: {}", if containers_mode { "Enabled" } else { "Disabled" });
    println!();

    print!("🔥 Start monitoring with these settings? [Y/n]: ");
    io::stdout().flush()?;
    let mut confirm = String::new();
    io::stdin().read_line(&mut confirm)?;
    
    if confirm.trim().to_lowercase() == "n" {
        println!("❌ Monitoring cancelled.");
        return Ok(None);
    }

    Ok(Some(InteractiveConfig {
        interface,
        json_mode,
        containers_mode,
    }))
}

fn choose_interface() -> Result<Option<String>, io::Error> {
    loop {
        println!("🔌 Available Network Interfaces:");
        
        let devices = match Device::list() {
            Ok(d) => d,
            Err(e) => {
                eprintln!("❌ Error listing devices: {}", e);
                return Ok(None);
            }
        };

        for (i, device) in devices.iter().enumerate() {
            println!("   {}. {}", i + 1, device.name);
        }
        
        println!("   0. Quit");
        println!();
        print!("📡 Select interface (number): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        match input.trim().parse::<usize>() {
            Ok(0) => return Ok(None), // Quit
            Ok(n) if n > 0 && n <= devices.len() => {
                return Ok(Some(devices[n - 1].name.clone()));
            }
            _ => {
                println!("❌ Invalid selection. Please try again.");
                println!();
            }
        }
    }
}

fn choose_mode() -> Result<(bool, bool), io::Error> {
    loop {
        println!("📊 Choose Output Mode:");
        println!("   1. Interactive TUI (recommended)");
        println!("   2. JSON output (5-second capture)");
        println!();
        print!("📊 Select mode (1-2): ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        let json_mode = match input.trim() {
            "1" => false,
            "2" => true,
            _ => {
                println!("❌ Invalid selection. Please choose 1 or 2.");
                println!();
                continue;
            }
        };

        // Now ask about container awareness
        loop {
            println!();
            println!("🐳 Enable Container Awareness?");
            println!("   This will identify and group processes by container");
            println!("   (Docker, Podman, LXC, etc.)");
            println!();
            print!("🐳 Enable containers? [Y/n]: ");
            io::stdout().flush()?;

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            
            let containers_mode = match input.trim().to_lowercase().as_str() {
                "" | "y" | "yes" => true,
                "n" | "no" => false,
                _ => {
                    println!("❌ Please enter Y for yes or N for no.");
                    continue;
                }
            };

            return Ok((json_mode, containers_mode));
        }
    }
} 