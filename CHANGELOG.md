# Changelog

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

