# Changelog

## [0.3.1] - 2025-06-21

### Added
- Introduced an automatic setup prompt on the first run to help users configure system-wide `sudo` access easily.
- Added version information to the command-line interface.

### Changed
- The command-line flag for specifying a network interface has been changed from `--interface` to `--iface` for conciseness. The legacy `--interface` flag is retained for backward compatibility.
- The traffic measurement duration for interface selection was adjusted to 5 seconds for better accuracy.
- The layout of the packet details view was updated to consolidate header columns for improved readability.
- The footer for export notifications now has a dynamic height to prevent UI jumps and ensure messages are fully visible.

### Improved
- The packet sorting logic in the UI has been refined for a more consistent user experience.
- Post-installation messages now provide clearer instructions for setting up system-wide access.
- Help messages for command-line arguments have been enhanced for better clarity.
- The installation script now provides more informative output to guide users.

## [0.3.0] - 2025-06-21

### Added
- **Packet History and Details View**: Introduced a new dedicated view to inspect individual packets for each process, offering deep-dive analysis capabilities.
- **Advanced Sorting and Filtering**: The packet details view now supports sorting by any column (timestamp, direction, protocol, etc.) and filtering with plain text or powerful regex patterns (e.g., `/regex:<pattern>`).
- **Performance-Oriented Caching**: Implemented multiple caching layers for packet data, pre-computed strings, and rendering styles to deliver a smooth, high-performance UI, even with thousands of packets.
- **Configurable Highlighting**: Users can now set custom thresholds in the settings menu to visually highlight large packets and frequent connections.
- **Service Name Resolution**: Network ports are now displayed with their corresponding service names (e.g., port 443 is shown as HTTPS) for better context.
- **Enhanced Export Notifications**: The UI now provides clear, persistent feedback on the status of packet data exports (success or failure).

### Changed
- **Performance Overhaul**: Re-architected data handling with virtual scrolling and optimized rendering logic, eliminating lag and ensuring a highly responsive interface.
- **Improved UI Readability**: The packet details view now features connection grouping, directional color-coding (light blue for sent, light green for received), and a responsive layout that adapts to different terminal widths.
- **Refined Key Event Management**: Streamlined keyboard navigation and commands within the packet details mode for a more intuitive user experience.

## [0.2.1] - 2025-06-17

### Added
- **Smart dependency detection system** - Automatically detects missing dependencies and provides installation guides
- Interactive dependency installation guides for missing components
- Platform-specific installation instructions (Windows/Linux)
- User-friendly prompts when dependencies are missing
- Detailed step-by-step installation guides for:
  - Npcap/WinPcap on Windows
  - libpcap on Linux

### Changed
- Improved error handling when packet capture dependencies are unavailable
- Enhanced guided setup to check dependencies before proceeding with configuration
- Better user experience when dependencies are missing - no more abrupt exits

### Technical Details
- Added new `dependencies` module for centralized dependency management
- Integrated dependency checks into both direct usage and interactive setup flows
- Added comprehensive installation guides with platform detection
- Maintained backward compatibility with existing functionality

## [0.2.0] - Previous Release

### Features
- Cross-platform support (Linux and Windows)
- New configuration reset tab
- Tool now measure which interfaces are the busiest then recommends which interfaces to choose
- Notification box size and behavior is adjusted to not take too much space and would dismiss itself after 5 seconds

