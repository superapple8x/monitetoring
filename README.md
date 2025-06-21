# Monitetoring

A real-time per-process network bandwidth monitoring tool for Linux and Windows, inspired by `nethogs`. Built with Rust and featuring a terminal UI powered by `ratatui`.

## Installation

### Recommended Installation

#### Windows

The easiest way to get started on Windows is to use the pre-compiled binary release.

1.  **Download the latest Windows release** from the [GitHub Releases](https://github.com/superapple8x/monitetoring/releases) page.
2.  **Extract the ZIP file** to a permanent folder (e.g., `C:\Program Files\monitetoring`).
3.  **Run the automated setup script**: Right-click on `setup_windows.bat` and select "Run as Administrator".

The setup script handles everything for you:
- ✅ Verifies Administrator privileges.
- ✅ Checks for the required **Npcap** dependency and guides you through the installation if it's missing.
- ✅ Prepares the application for use.

After setup, you can run `monitetoring.exe` as Administrator.

#### Linux (via Cargo)

For Linux, the recommended method is to install via `cargo`. This requires the Rust toolchain, which includes `cargo`.

**1. Install Rust & Cargo**

Choose the command for your distribution:

<details>
<summary><b>Ubuntu / Debian</b></summary>

```bash
# Install dependencies and Rust/Cargo
sudo apt update
sudo apt install -y curl build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```
</details>

<details>
<summary><b>Fedora / RHEL / CentOS</b></summary>

```bash
# Install dependencies and Rust/Cargo
sudo dnf install -y curl pkg-config openssl-devel
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```
</details>

After installation, you may need to restart your terminal or run `source "$HOME/.cargo/env"` for the `cargo` command to be available.

**2. Install Monitetoring**
```bash
# This single command downloads, compiles, and installs the application
cargo install monitetoring
```
Once installed, run the application with `sudo monitetoring`.

**3. (Optional) Set up system-wide access**

For easier `sudo` usage, you can set up system-wide access:

```bash
# Download and run the system-wide installation script
curl -sSL https://raw.githubusercontent.com/superapple8x/monitetoring/main/install_system_wide.sh | bash

# Or if you have the repository cloned:
./install_system_wide.sh
```

This sets up system-wide access so you can run `sudo monitetoring` from anywhere. Future updates via `cargo install` will automatically be available system-wide.

---

### Building from Source (For Developers)

If you want to contribute, modify, or build the project manually, follow these steps. This is the only path that requires you to install the Rust compiler.

#### 1. Clone the Repository

```bash
git clone https://github.com/superapple8x/monitetoring
cd monitetoring
```

#### 2. Install Rust Toolchain (if you don't have it)

If you don't have Rust, install it using `rustup`.

**On Linux:**

Choose the command for your distribution:

<details>
<summary><b>Ubuntu / Debian</b></summary>

```bash
# Install dependencies and Rust/Cargo
sudo apt update
sudo apt install -y curl build-essential pkg-config libssl-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```
</details>

<details>
<summary><b>Fedora / RHEL / CentOS</b></summary>

```bash
# Install dependencies and Rust/Cargo
sudo dnf install -y curl pkg-config openssl-devel
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```
</details>

After installation, you may need to restart your terminal or run `source "$HOME/.cargo/env"` for the `cargo` command to be available.

**On Windows:**
- Download and run `rustup-init.exe` from [rustup.rs](https://rustup.rs/).
- Ensure you also install the C++ build tools when prompted by the installer.

#### 3. Build the Application

**On Linux:**
```bash
cargo build --release

# To run it:
sudo ./target/release/monitetoring
```

**On Windows:**
Building on Windows has an additional dependency: the **Npcap SDK**.

- **A. Install Npcap Runtime**: Download and install the latest "Npcap installer" from the [official website](https://npcap.com/#download).
  - ⚠️ **Critical**: During installation, check the box for "Install Npcap in WinPcap API-compatible Mode".
- **B. Install Npcap SDK**: Download the "Npcap SDK" from the same page and unzip it.
- **C. Build the code**:
  ```cmd
  # You can either set an environment variable to the SDK location...
  set NPCAP_SDK_PATH=C:\path\to\npcap-sdk
  
  # ...or place the SDK's /Lib/x64 folder contents in the right place.
  # See build.rs for details.

  cargo build --release
  ```

After building, run `./target/release/monitetoring.exe` as Administrator.

#### Windows Troubleshooting

**Build fails with "wpcap.lib not found"**:
- ✅ You have the Npcap *Runtime* but are missing the **Npcap SDK**. They are separate downloads.
- ✅ Ensure the `NPCAP_SDK_PATH` environment variable is set correctly or that you've placed the library files where the build script can find them.

**Application crashes or "No interfaces found"**:
- ✅ Run the executable as Administrator.
- ✅ Verify Npcap was installed with "WinPcap API-compatible Mode" enabled.
- ✅ Check that the `npcap` service is running: `sc query npcap`.

---

## Quick Start

### Interactive Mode

Simply run without arguments for guided setup:

```bash
sudo monitetoring
```

This will:
1. Show available network interfaces
2. Let you choose monitoring mode (TUI or JSON)
3. Configure container awareness
4. Save your preferences for future use

### Direct Usage

```bash
# Both `--iface` and the legacy `--interface` are accepted. The examples below use the primary flag.
sudo monitetoring --iface any
sudo monitetoring --iface eth0 --json
sudo monitetoring --iface eth0 --containers
sudo monitetoring --reset
```

## Features

- Real-time monitoring of network bandwidth usage per process
- Container awareness for Docker, Podman, LXC, containerd, and systemd-nspawn
- Interactive setup when run without arguments
- **Smart dependency detection with installation guides** - Automatically detects missing dependencies (like Npcap on Windows) and provides step-by-step installation instructions
- Configuration persistence between runs
- TUI interface or JSON output for scripting
- Sortable columns (PID, process name, sent/received bytes, container name, user name)
- Human-readable bandwidth formatting (B, KB, MB, GB, TB)
- Network interface selection
- Works out of the box – configuration is purely optional

## Screenshots

**Main View**

![Main View](doc/main_view.png)

**Bandwidth – System Stack**

![Stacked Bandwidth](doc/bandwidth_stacked.png)

**Bandwidth – Process Lines**

![Process Bandwidth](doc/bandwidth_process.png)

**System Overview**

![System Overview](doc/system_overview.png)

## Command Line Options

```
Usage: monitetoring [OPTIONS]

Options:
  -i, --iface <IFACE>       Network interface to monitor [default: any] (alias: --interface)
  -j, --json                Output in JSON format instead of TUI
  -c, --containers          Enable container detection and display
      --reset               Reset saved configuration and exit
  -h, --help                Print help
  -V, --version             Print version
```

## Terminal UI

The TUI interface provides:

- Process bandwidth usage updates every second
- Sortable columns via keyboard shortcuts
- Container information when enabled
- Human-readable bandwidth display

### Interface Modes

Monitetoring has three main interface modes that you can cycle through using the `Tab` key:

#### 1. Main Mode (Default)
- **Purpose**: Real-time process monitoring with detailed table view
- **Features**: 
  - Sortable process table showing PID, name, bandwidth usage
  - Process selection and action panel (kill, set alerts)
  - Container information (when enabled)
  - Network totals display

#### 2. Overview Mode
- **Purpose**: System-wide dashboard with quota management
- **Features**:
  - Data usage gauge with quota visualization
  - Protocol breakdown (TCP, UDP, ICMP, Other) with charts
  - System information (uptime, process count, alert status)
  - Alert threshold progress bars for monitored processes
  - Quota management controls

#### 3. Bandwidth Mode
- **Purpose**: Visual bandwidth analysis with charts
- **Features**:
  - Real-time bandwidth charts (process lines or system stacked)
  - Compact process table alongside charts
  - Chart type switching (individual process vs. system-wide)
  - Metrics mode switching (combined, send-only, receive-only)

### Keyboard Controls

#### Navigation
| Key | Action |
|-----|--------|
| `q` | Quit application |
| `Tab` | Switch mode |
| `Esc` | Return to main mode from overview |

#### Main Mode
| Key | Action |
|-----|--------|
| `p` | Sort by PID |
| `n` | Sort by process name |
| `u` | Sort by user |
| `s` | Sort by bytes sent |
| `r` | Sort by bytes received |
| `c` | Sort by container name (when containers enabled) |
| `d` | Toggle sort direction (ascending/descending) |
| `↑/↓` | Select process |
| `Enter` | Show actions for selected process |

#### Bandwidth Mode
| Key | Action |
|-----|--------|
| `t` | Toggle chart type (process lines/system stacked) |
| `m` | Toggle metrics mode (combined/send only/receive only) |

#### Overview Mode
| Key | Action |
|-----|--------|
| `+/-` | Adjust data quota threshold (±100MB) |
| `r` | Reset quota exceeded state |

## JSON Output Mode

For integration with monitoring systems or scripts:

```bash
sudo monitetoring --iface eth0 --json --containers
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

## Container Support

Monitetoring can detect processes running in container runtimes:

- Docker
- Podman
- LXC
- containerd
- systemd-nspawn

Container detection reads `/proc/[PID]/cgroup` to identify container membership.

**Note**: Due to Docker's network namespace isolation, containerized processes may not show network traffic in the host's monitoring view. This is expected behavior - containers use separate network namespaces.

## Configuration

Monitetoring automatically saves your preferences to:
- Linux: `~/.config/monitetoring/config.json`

The configuration includes:
- Default network interface
- Output mode preference (TUI/JSON)
- Container detection setting

Reset configuration:
```bash
sudo monitetoring --reset
```

## Technical Details

### Dependencies

The project uses these key dependencies:
- `pcap` - Packet capture
- `ratatui` - Terminal UI
- `tokio` - Async runtime
- `clap` - CLI parsing
- `procfs` - Process information
- `serde` - JSON serialization

### Architecture

- Hybrid async/threaded design with dedicated packet capture thread
- Modular structure separating capture, processing, and display
- Linux-focused implementation

### Network Monitoring

- Uses `libpcap` for packet capture
- Parses TCP/UDP packets to extract process information
- Maps network sockets to processes via `/proc/net/{tcp,udp}`
- Tracks per-process bandwidth in real-time

## Contributing

Contributions are welcome. Areas for improvement:

- Additional container runtime support
- Performance optimizations
- Additional output formats
- Enhanced filtering options

## License

This project is licensed under the GPL-2.0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by `nethogs`
- Built with Rust
- UI powered by `ratatui`

## Issues & Support

If you encounter any issues:

1. Ensure you're running with sudo/root privileges
2. Check that your network interface exists and is active
3. Verify container runtime is properly configured (if using --containers)
4. Check the logs for any error messages

For bug reports and feature requests, please use the GitHub issue tracker. 

### "Command not found" when using `sudo`

If you installed Monitetoring with `cargo install monitetoring`, you may get a *command not found* error when running `sudo monitetoring`.

Solutions:

1. **Set up system-wide access (recommended):**
   ```bash
   curl -sSL https://raw.githubusercontent.com/superapple8x/monitetoring/main/install_system_wide.sh | bash
   # Then you can simply run: sudo monitetoring --iface any
   ```

2. Use this command instead:
   ```bash
   sudo $HOME/.cargo/bin/monitetoring --iface any
   ```

3. Keep your current `PATH` when escalating privileges:
   ```bash
   sudo -E monitetoring --iface any
   # or
   sudo env "PATH=$PATH" monitetoring --iface any
   ```

4. Add Cargo's bin directory to the `secure_path` in `/etc/sudoers` (requires root privileges):
   ```bash
   sudo visudo
   # Add /home/<user>/.cargo/bin to the secure_path setting, e.g.
   # Defaults    secure_path = /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/<user>/.cargo/bin
   ```

The first option is recommended as it's permanent, automatic, and works for all users.


