fn main() {
    if cfg!(target_os = "windows") {
        // This build script's purpose is to tell the Rust compiler (rustc) where to find
        // the `wpcap.lib` library file. This file is part of the Npcap SDK installation and
        // is required by the `pcap` crate to link against the Npcap packet capture driver.

        // IMPORTANT: There are TWO separate Npcap downloads:
        // 1. Npcap Runtime Installer - installs drivers for applications like Wireshark
        // 2. Npcap SDK - includes development files (.lib) needed to BUILD applications
        // You need BOTH, but this build script specifically looks for the SDK.

        // First, check if the user has set the `NPCAP_SDK` environment variable
        if let Ok(sdk_dir) = std::env::var("NPCAP_SDK") {
            if try_link_from_path(&sdk_dir, "NPCAP_SDK environment variable") {
                return;
            }
        }

        // Try to find the Npcap SDK in common installation locations
        let sdk_paths = [
            "C:\\Program Files\\Npcap SDK",    // Official SDK installer default
            "C:\\Npcap-SDK",                   // Manual extraction location
            "C:\\Npcap-SDK-1.13",             // Version-specific directory
            "C:\\Npcap-SDK-1.14",
            "C:\\Npcap-SDK-1.15",
            "C:\\Program Files\\Npcap",       // Sometimes SDK installs here
        ];

        for path in &sdk_paths {
            if try_link_from_path(path, &format!("SDK path: {}", path)) {
                return;
            }
        }

        // Check if Npcap Runtime is installed (to provide better error message)
        let runtime_installed = check_npcap_runtime_installed();

        // Build failed - provide comprehensive error message
        if runtime_installed {
            panic!(
                "\n🔧 BUILD FAILED: Npcap SDK not found\n\
                \n\
                ✅ Good news: Npcap Runtime is installed\n\
                ❌ Missing: Npcap SDK (required for building)\n\
                \n\
                📥 SOLUTION: Download and install the Npcap SDK\n\
                \n\
                                 1. Go to: https://npcap.com/#download\n\
                 2. Look for 'Npcap SDK [version] (ZIP)' (separate from the runtime installer)\n\
                 3. Download and extract the SDK ZIP file\n\
                4. Retry building\n\
                \n\
                💡 Alternative: Set NPCAP_SDK environment variable to SDK location\n\
                   Example: set NPCAP_SDK=C:\\path\\to\\npcap-sdk\n\
                \n\
                📂 Expected SDK structure:\n\
                   SDK_DIR/\n\
                   ├── Lib/\n\
                   │   ├── x64/wpcap.lib    ← This file is required\n\
                   │   └── wpcap.lib\n\
                   └── Include/\n"
            );
        } else {
            panic!(
                "\n🔧 BUILD FAILED: Npcap not found\n\
                \n\
                ❌ Missing: Both Npcap Runtime AND SDK\n\
                \n\
                📥 SOLUTION: Install both components\n\
                \n\
                                 1. Go to: https://npcap.com/#download\n\
                 2. Download and install 'Npcap [version] installer for Windows'\n\
                    - Choose 'Install Npcap in WinPcap API-compatible Mode'\n\
                 3. Download and extract 'Npcap SDK [version] (ZIP)' (separate download)\n\
                4. Retry building\n\
                \n\
                💡 You need BOTH:\n\
                   • Npcap Runtime (for packet capture to work)\n\
                   • Npcap SDK (for this project to compile)\n\
                \n\
                🔍 For troubleshooting: set NPCAP_SDK environment variable\n"
            );
        }
    }
}

/// Try to link against wpcap.lib from the given directory
fn try_link_from_path(base_path: &str, source_description: &str) -> bool {
    let base = std::path::Path::new(base_path);
    
    // Try x64 library first (most common on modern systems)
    let lib_x64 = base.join("Lib").join("x64");
    if lib_x64.join("wpcap.lib").exists() {
        println!("cargo:rustc-link-search=native={}", lib_x64.display());
        println!("cargo:rustc-link-lib=static=wpcap");
        println!("cargo:warning=Found wpcap.lib via {}: {}", source_description, lib_x64.display());
        return true;
    }
    
    // Fallback to generic Lib directory
    let lib_generic = base.join("Lib");
    if lib_generic.join("wpcap.lib").exists() {
        println!("cargo:rustc-link-search=native={}", lib_generic.display());
        println!("cargo:rustc-link-lib=static=wpcap");
        println!("cargo:warning=Found wpcap.lib via {}: {}", source_description, lib_generic.display());
        return true;
    }
    
    false
}

/// Check if Npcap runtime is installed by looking for service or DLLs
fn check_npcap_runtime_installed() -> bool {
    // Check for Npcap service
    if let Ok(output) = std::process::Command::new("sc")
        .args(["query", "npcap"])
        .output() 
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("RUNNING") || stdout.contains("STOPPED") {
            return true;
        }
    }
    
    // Check for WinPcap service (legacy)
    if let Ok(output) = std::process::Command::new("sc")
        .args(["query", "npf"])
        .output() 
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("RUNNING") || stdout.contains("STOPPED") {
            return true;
        }
    }
    
    // Check for common DLL locations
    let dll_paths = [
        "C:\\Windows\\System32\\wpcap.dll",
        "C:\\Windows\\System32\\packet.dll",
        "C:\\Windows\\SysWOW64\\wpcap.dll",
        "C:\\Windows\\SysWOW64\\packet.dll",
    ];
    
    for path in &dll_paths {
        if std::path::Path::new(path).exists() {
            return true;
        }
    }
    
    false
} 