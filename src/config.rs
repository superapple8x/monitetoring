use clap::Parser;

#[derive(Parser)]
pub struct Cli {
    #[arg(long)]
    pub iface: Option<String>,
    #[arg(long)]
    pub json: bool,
    #[arg(long)]
    pub containers: bool,
} 