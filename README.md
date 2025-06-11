# Monitetoring

A real-time per-process network bandwidth monitoring tool for Linux, inspired by `nethogs`. Built with Rust and featuring a beautiful terminal UI powered by `ratatui`.

## 🚀 Features

- **Real-time monitoring**: Track network bandwidth usage per process in real-time
- **Container awareness**: Detect and display containerized processes (Docker, Podman, LXC, containerd, systemd-nspawn)
- **Interactive setup**: Guided configuration when no arguments provided
- **Persistent configuration**: Save your preferences and quick-start on subsequent runs
- **Multiple output formats**: Beautiful TUI interface or JSON output for scripting
- **Intelligent sorting**: Sort by PID, process name, sent/received bytes, or container name
- **Human-readable metrics**: Automatic formatting of bandwidth (B, KB, MB, GB, TB)
- **Network interface selection**: Monitor specific interfaces or all available ones
- **Zero configuration**: Works out of the box with sensible defaults

## 📦 Installation

### Prerequisites

- Linux system (kernel 2.6+ recommended)
- Rust 1.70+ (for building from source)
- Root/sudo privileges (required for packet capture)

### From Source

```bash
git clone https://github.com/superapple8x/monitetoring
cd monitetoring
cargo build --release
sudo cp target/release/monitetoring /usr/local/bin/
```

### Using Cargo Install

If the project is published to crates.io:

```bash
cargo install monitetoring
```

### Manual Installation

After building from source, you can install system-wide:

```bash
# Build the project
cargo build --release

# Install to system (requires sudo)
sudo cp target/release/monitetoring /usr/local/bin/

# Or install to user directory (no sudo needed)
mkdir -p ~/.local/bin
cp target/release/monitetoring ~/.local/bin/
# Make sure ~/.local/bin is in your PATH
```

### Dependencies

The project uses these key dependencies:
- `pcap` - Packet capture
- `ratatui` - Terminal UI
- `tokio` - Async runtime
- `clap` - CLI parsing
- `procfs` - Process information
- `serde` - JSON serialization

## 🎯 Quick Start

### Interactive Mode (Recommended)

Simply run without arguments for guided setup:

```bash
# From source (development)
sudo cargo run

# If installed system-wide
sudo monitetoring
```

This will:
1. Show available network interfaces
2. Let you choose monitoring mode (TUI or JSON)
3. Configure container awareness
4. Save your preferences for future use

### Direct Usage

```bash
# From source (development)
sudo cargo run -- --interface any
sudo cargo run -- --interface eth0 --json
sudo cargo run -- --interface eth0 --containers
sudo cargo run -- --reset

# If installed system-wide
sudo monitetoring --interface any
sudo monitetoring --interface eth0 --json
sudo monitetoring --interface eth0 --containers
sudo monitetoring --reset
```

## 📋 Command Line Options

```
Usage: monitetoring [OPTIONS]

Options:
  -i, --interface <INTERFACE>  Network interface to monitor [default: any]
  -j, --json                   Output in JSON format instead of TUI
  -c, --containers             Enable container detection and display
      --reset                  Reset saved configuration and exit
  -h, --help                   Print help
  -V, --version                Print version
```

## 🖥️ Terminal UI

The TUI interface provides:

- **Real-time updates**: Process bandwidth usage updates every second
- **Sortable columns**: Press keys to sort by different criteria
- **Container information**: When enabled, shows container names
- **Formatted metrics**: Human-readable bandwidth display

### Keyboard Controls

| Key | Action |
|-----|--------|
| `q` | Quit |
| `p` | Sort by PID |
| `n` | Sort by process name |
| `s` | Sort by bytes sent |
| `r` | Sort by bytes received |
| `c` | Sort by container name (when containers enabled) |



## 📊 JSON Output Mode

Perfect for integration with monitoring systems or custom scripts:

```bash
# From source (development)
sudo cargo run -- --interface eth0 --json --containers

# If installed system-wide
sudo monitetoring --interface eth0 --json --containers
```

```json
[
  {
    "pid": 1234,
    "name": "firefox",
    "sent_bytes": 2621440,
    "received_bytes": 15925248,
    "sent_formatted": "2.5 MB",
    "received_formatted": "15.2 MB",
    "container_name": null
  },
  {
    "pid": 5678,
    "name": "nginx",
    "sent_bytes": 876544,
    "received_bytes": 1258291,
    "sent_formatted": "856 KB",
    "received_formatted": "1.2 MB",
    "container_name": "webserver"
  }
]
```

## 🐳 Container Support

Monitetoring can detect processes running in various container runtimes:

- **Docker**: Full container name detection
- **Podman**: Container identification support  
- **LXC**: Linux Containers support
- **containerd**: Container runtime support
- **systemd-nspawn**: Systemd containers

Container detection reads `/proc/[PID]/cgroup` to identify container membership.

**Note**: Due to Docker's network namespace isolation, containerized processes may not show network traffic in the host's monitoring view. This is expected behavior - containers use separate network namespaces.

## ⚙️ Configuration

Monitetoring automatically saves your preferences to:
- Linux: `~/.config/monitetoring/config.json`

The configuration includes:
- Default network interface
- Output mode preference (TUI/JSON)
- Container detection setting

Reset configuration:
```bash
# From source (development)
sudo cargo run -- --reset

# If installed system-wide
sudo monitetoring --reset
```

## 🔧 Technical Details

### Architecture

- **Hybrid async/threaded design**: Dedicated packet capture thread with async UI
- **Modular structure**: Clean separation between capture, processing, and display
- **Memory efficient**: Minimal memory footprint with efficient data structures
- **Cross-platform ready**: Linux-focused but architecturally portable

### Network Monitoring

- Uses `libpcap` for efficient packet capture
- Parses TCP/UDP packets to extract process information
- Maps network sockets to processes via `/proc/net/{tcp,udp}`
- Tracks per-process bandwidth in real-time

### Performance

- Minimal CPU overhead
- Efficient packet filtering
- Optimized data structures for real-time updates
- Async UI prevents blocking during heavy network traffic

## 🤝 Contributing

Contributions are welcome! Areas for improvement:

- Additional container runtime support
- Windows/macOS compatibility
- Performance optimizations
- Additional output formats
- Enhanced filtering options

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by the excellent `nethogs` tool
- Built with the amazing Rust ecosystem
- UI powered by the fantastic `ratatui` library

## 🐛 Issues & Support

If you encounter any issues:

1. Ensure you're running with sudo/root privileges
2. Check that your network interface exists and is active
3. Verify container runtime is properly configured (if using --containers)
4. Check the logs for any error messages

For bug reports and feature requests, please use the GitHub issue tracker. 