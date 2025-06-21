use clap::Parser;
use crate::types::Alert;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::io;

fn default_large_packet_threshold() -> usize {
    100_000
}

fn default_frequent_connection_threshold() -> usize {
    20
}

#[derive(Parser)]
pub struct Cli {
    // Accepts `--iface` (primary) and `--interface` (legacy alias for backward compatibility)
    #[arg(short = 'i', long = "iface", alias = "interface", help = "Network interface to monitor [default: any] (alias: --interface)")]
    pub iface: Option<String>,
    #[arg(long, help = "Output in JSON format instead of TUI")]
    pub json: bool,
    #[arg(long, help = "Enable container detection and display")]
    pub containers: bool,
    #[arg(long, help = "Reset saved configuration and exit")]
    pub reset: bool,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SavedConfig {
    pub interface: String,
    pub json_mode: bool,
    pub containers_mode: bool,
    #[serde(default)]
    pub show_total_columns: bool,
    #[serde(default)]
    pub alerts: Vec<Alert>,
    #[serde(default = "default_large_packet_threshold")]
    pub large_packet_threshold: usize,
    #[serde(default = "default_frequent_connection_threshold")]
    pub frequent_connection_threshold: usize,
    #[serde(default)]
    pub setup_offered: bool,
}

pub fn get_config_path() -> Result<PathBuf, io::Error> {
    let config_dir = if let Some(config_dir) = dirs::config_dir() {
        config_dir.join("monitetoring")
    } else {
        // Fallback to home directory
        dirs::home_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not find home directory"))?
            .join(".monitetoring")
    };
    
    // Create directory if it doesn't exist
    fs::create_dir_all(&config_dir)?;
    
    Ok(config_dir.join("config.json"))
}

pub fn save_config(config: &SavedConfig) -> Result<(), io::Error> {
    let config_path = get_config_path()?;
    let json = serde_json::to_string_pretty(config)?;
    fs::write(config_path, json)?;
    Ok(())
}

pub fn load_config() -> Option<SavedConfig> {
    let config_path = get_config_path().ok()?;
    if !config_path.exists() {
        return None;
    }
    
    let content = fs::read_to_string(config_path).ok()?;
    serde_json::from_str(&content).ok()
}

pub fn reset_config() -> Result<bool, io::Error> {
    let config_path = get_config_path()?;
    if config_path.exists() {
        fs::remove_file(config_path)?;
        Ok(true) // Config was deleted
    } else {
        Ok(false) // No config existed
    }
} 