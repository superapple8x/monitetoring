#[cfg(target_os = "windows")]
use std::process::Command;

#[derive(Debug, Clone)]
pub struct DependencyInfo {
    pub name: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone)]
pub struct InstallationGuide {
    pub dependency: DependencyInfo,
    pub platform: &'static str,
    pub install_steps: Vec<&'static str>,
    pub download_url: Option<&'static str>,
    pub additional_notes: Vec<&'static str>,
}

pub struct DependencyChecker;

impl DependencyChecker {
    /// Check all required dependencies and return missing ones with installation guides
    pub fn check_dependencies() -> Vec<InstallationGuide> {
        let mut missing_deps = Vec::new();
        
        // Check platform-specific dependencies
        #[cfg(target_os = "windows")]
        {
            if !Self::check_npcap_windows() {
                missing_deps.push(Self::get_npcap_guide_windows());
            }
        }
        
        #[cfg(target_os = "linux")]
        {
            if !Self::check_libpcap_linux() {
                missing_deps.push(Self::get_libpcap_guide_linux());
            }
        }
        
        missing_deps
    }
    

    
    /// Windows: Check if Npcap or WinPcap is installed
    #[cfg(target_os = "windows")]
    fn check_npcap_windows() -> bool {
        // Check if npcap service is installed
        let npcap_check = Command::new("sc")
            .args(["query", "npcap"])
            .output();
        
        if let Ok(result) = npcap_check {
            let output_str = String::from_utf8_lossy(&result.stdout);
            if output_str.contains("RUNNING") || output_str.contains("STOPPED") {
                return true; // Npcap service exists
            }
        }
        
        // Fallback: Check for WinPcap
        let winpcap_check = Command::new("sc")
            .args(["query", "npf"])
            .output();
            
        if let Ok(result) = winpcap_check {
            let output_str = String::from_utf8_lossy(&result.stdout);
            if output_str.contains("RUNNING") || output_str.contains("STOPPED") {
                return true; // WinPcap service exists
            }
        }
        
        false
    }
    
    /// Linux: Check if libpcap is available (usually always available on Linux)
    #[cfg(target_os = "linux")]
    fn check_libpcap_linux() -> bool {
        // On Linux, pcap is usually available through the kernel
        // We can do a simple check by trying to list network devices
        match pcap::Device::list() {
            Ok(_) => true,
            Err(_) => false,
        }
    }
    
    /// Get Npcap installation guide for Windows
    #[cfg(target_os = "windows")]
    fn get_npcap_guide_windows() -> InstallationGuide {
        InstallationGuide {
            dependency: DependencyInfo {
                name: "Npcap",
                description: "Network packet capture library (required for monitoring network traffic)",
            },
            platform: "Windows",
            install_steps: vec![
                "1. Visit the Npcap website at https://npcap.com/",
                "2. Download the latest Npcap installer",
                "3. Run the installer as Administrator",
                "4. During installation, make sure to check 'Install Npcap in WinPcap API-compatible Mode'",
                "5. Complete the installation and reboot if prompted",
                "6. Run monitetoring as Administrator after installation"
            ],
            download_url: Some("https://npcap.com/"),
            additional_notes: vec![
                "• Npcap is free and safe - it's the standard packet capture library used by Wireshark",
                "• You need Administrator privileges to capture network packets on Windows",
                "• If you have WinPcap installed, Npcap can coexist with it",
                "• Some antivirus software may flag packet capture tools - this is normal"
            ],
        }
    }
    
    /// Get libpcap installation guide for Linux
    #[cfg(target_os = "linux")]
    fn get_libpcap_guide_linux() -> InstallationGuide {
        InstallationGuide {
            dependency: DependencyInfo {
                name: "libpcap",
                description: "Network packet capture library (should be available on most Linux systems)",
            },
            platform: "Linux",
            install_steps: vec![
                "Ubuntu/Debian: sudo apt-get update && sudo apt-get install libpcap-dev",
                "Fedora/RHEL/CentOS: sudo dnf install libpcap-devel (or sudo yum install libpcap-devel)",
                "Arch Linux: sudo pacman -S libpcap",
                "OpenSUSE: sudo zypper install libpcap-devel",
                "Alpine Linux: sudo apk add libpcap-dev"
            ],
            download_url: None,
            additional_notes: vec![
                "• Most Linux distributions include libpcap by default",
                "• You need root privileges to capture network packets",
                "• If the above commands don't work, consult your distribution's documentation",
                "• You can also try running: sudo setcap cap_net_raw,cap_net_admin=eip ./monitetoring"
            ],
        }
    }
    
    /// Display detailed installation guide for missing dependencies
    pub fn display_installation_guides(guides: &[InstallationGuide]) {
        if guides.is_empty() {
            return;
        }
        
        println!("🔧 DEPENDENCY INSTALLATION GUIDE");
        println!("{}", "=".repeat(50));
        println!();
        
        println!("⚠️  Some required dependencies are missing. Don't worry - we'll help you install them!");
        println!();
        
        for (i, guide) in guides.iter().enumerate() {
            if i > 0 {
                println!();
                println!("{}", "-".repeat(40));
                println!();
            }
            
            println!("📦 {}: {}", guide.dependency.name, guide.dependency.description);
            println!("🖥️  Platform: {}", guide.platform);
            println!();
            
            if let Some(url) = guide.download_url {
                println!("🌐 Download URL: {}", url);
                println!();
            }
            
            println!("📋 Installation Steps:");
            for step in &guide.install_steps {
                println!("   {}", step);
            }
            println!();
            
            if !guide.additional_notes.is_empty() {
                println!("💡 Additional Notes:");
                for note in &guide.additional_notes {
                    println!("   {}", note);
                }
                println!();
            }
        }
        
        println!("🚀 After installing the dependencies, restart monitetoring to continue!");
        println!();
    }
    
    /// Prompt user whether to continue with installation or exit
    pub fn prompt_installation_action() -> std::io::Result<bool> {
        use std::io::{self, Write};
        
        println!("What would you like to do?");
        println!("1. 📖 Show installation guides and exit (recommended)");
        println!("2. ⏭️  Skip dependency check and try to continue anyway");
        println!("3. ❌ Exit now");
        println!();
        
        loop {
            print!("Please choose (1/2/3): ");
            io::stdout().flush()?;
            
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();
            
            match input {
                "1" => return Ok(true),  // Show guides and exit
                "2" => return Ok(false), // Skip and continue
                "3" => std::process::exit(0),
                _ => {
                    println!("❌ Please enter 1, 2, or 3.");
                    println!();
                }
            }
        }
    }
}

/// Integration point for the guided setup - checks dependencies and handles missing ones
pub fn handle_dependencies_in_setup() -> std::io::Result<bool> {
    let missing_deps = DependencyChecker::check_dependencies();
    
    if missing_deps.is_empty() {
        // All dependencies are available
        return Ok(true);
    }
    
    // Some dependencies are missing - show guides
    println!();
    DependencyChecker::display_installation_guides(&missing_deps);
    
    // Ask user what they want to do
    let show_guides = DependencyChecker::prompt_installation_action()?;
    
    if show_guides {
        // User chose to see guides and exit
        println!("👋 Run monitetoring again after installing the required dependencies!");
        return Ok(false); // Don't continue with setup
    } else {
        // User chose to skip and continue anyway
        println!("⚠️  Continuing without all dependencies - some features may not work properly.");
        println!();
        return Ok(true); // Continue with setup
    }
} 