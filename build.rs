fn main() {
    if cfg!(target_os = "windows") {
        // This build script's purpose is to tell the Rust compiler (rustc) where to find
        // the `wpcap.lib` library file. This file is part of the Npcap installation and
        // is required by the `pcap` crate to link against the Npcap packet capture driver.

        // The MSVC linker (`link.exe`) doesn't automatically know the Npcap installation
        // path, so we have to provide it manually.

        // First, check if the user has set the `NPCAP_SDK` environment variable, which is the
        // most reliable method if they have the full SDK installed.
        if let Ok(sdk_dir) = std::env::var("NPCAP_SDK") {
            // If the variable is set, construct the full path to the 64-bit library folder.
            let lib_path = std::path::Path::new(&sdk_dir).join("Lib\\x64");
            if lib_path.exists() {
                // This command tells rustc to add the specified path to the linker's search paths.
                println!("cargo:rustc-link-search=native={}", lib_path.display());
                // This command tells rustc to link against the `wpcap` library.
                println!("cargo:rustc-link-lib=static=wpcap");
                return;
            }
        }

        // If the environment variable isn't set, we'll try to find the Npcap installation
        // in its default locations. This covers the majority of standard installations.
        let common_paths = [
            "C:\\Program Files\\Npcap",
            "C:\\Npcap-SDK-1.13", // A common default path for the SDK installer
            "C:\\Npcap-SDK",
        ];

        for path in &common_paths {
            // Check for the 64-bit library directory first.
            let lib_path_x64 = std::path::Path::new(path).join("Lib\\x64");
            if lib_path_x64.exists() {
                println!("cargo:rustc-link-search=native={}", lib_path_x64.display());
                println!("cargo:rustc-link-lib=static=wpcap");
                return;
            }
            // As a fallback, check for a generic 'Lib' directory.
            let lib_path = std::path::Path::new(path).join("Lib");
            if lib_path.exists() {
                println!("cargo:rustc-link-search=native={}", lib_path.display());
                println!("cargo:rustc-link-lib=static=wpcap");
                return;
            }
        }

        // If the library still hasn't been found after checking all common locations,
        // we'll cause the build to fail with a clear, helpful error message.
        panic!(
            "Build failed: Could not find `wpcap.lib`. \n\
            Please ensure Npcap is installed from https://npcap.com/. \n\
            If you installed the Npcap SDK, try setting the `NPCAP_SDK` environment variable to the SDK directory."
        );
    }
} 