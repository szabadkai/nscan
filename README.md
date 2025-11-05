# nscan - Modern Network Scanner

A professional network scanner CLI application with a modern, animated terminal UI that discovers all devices on a local network and provides comprehensive device information.

## Features

- 🚀 **Fast Discovery** - Quick device detection using multiple scanning techniques
- 🎯 **Comprehensive Information** - IP, MAC, hostname, OS, manufacturer, and device type
- 🎨 **Beautiful UI** - Modern terminal interface with animations and gradients
- 📊 **Multiple Output Formats** - Interactive UI, JSON, CSV, or table
- 🔍 **Multiple Scanning Methods** - ARP, Nmap, and passive tcpdump monitoring
- 🏷️ **Automatic Device Classification** - Infers device type from available data
- 💾 **Export Results** - Save scan results in various formats
- 🔄 **Continuous Monitoring** - Watch mode for real-time network monitoring

## Requirements

- **Node.js** 18.0.0 or higher
- **nmap** (required) - For network scanning
- **tcpdump** (optional) - For passive monitoring
- **arp-scan** (optional) - For faster ARP discovery
- **Root/sudo privileges** - Required for network interface access

### Installing Dependencies

#### macOS
```bash
brew install nmap
# tcpdump is pre-installed
brew install arp-scan  # optional
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install nmap tcpdump arp-scan
```

#### Windows
- Download nmap from https://nmap.org/download.html
- Install WinPcap or Npcap for tcpdump functionality

## Installation

### From Source

```bash
# Clone or download the project
cd nscan

# Install dependencies
npm install

# Run directly
sudo npm start

# Or install globally
sudo npm link
sudo nscan
```

### Build Executables

Build standalone executables that don't require Node.js:

```bash
# Build for all platforms
npm run build

# Build for specific platform
npm run build:linux   # Linux x64
npm run build:macos   # macOS (Intel & ARM)
npm run build:win     # Windows x64
```

Executables will be in the `dist/` directory.

## Usage

### Basic Usage

```bash
# Interactive mode with auto-detected network
sudo nscan

# Scan specific network range
sudo nscan --range 192.168.1.0/24

# Specify network interface
sudo nscan --interface en0

# Demo mode (no sudo/nmap required - for testing UI)
nscan --demo
```

### Advanced Usage

```bash
# Fast scan without OS detection
sudo nscan --fast --no-os

# Passive mode only (no active probes)
sudo nscan --passive

# Continuous monitoring mode
sudo nscan --watch

# Export results to file
sudo nscan --export devices.json

# Different output formats
sudo nscan --format json
sudo nscan --format csv --export devices.csv
sudo nscan --format table
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-r, --range <cidr>` | Network range to scan (e.g., 192.168.1.0/24) |
| `-i, --interface <name>` | Network interface to use |
| `-p, --passive` | Passive mode only (no active probes) |
| `-w, --watch` | Continuous monitoring mode |
| `-e, --export <file>` | Export results to file |
| `-f, --format <type>` | Output format: interactive, json, csv, table |
| `-v, --verbose` | Verbose output |
| `--no-os` | Skip OS detection (faster) |
| `--fast` | Fast mode (skip detailed scans) |
| `-t, --timeout <seconds>` | Scan timeout per host (default: 30) |
| `--demo` | Demo mode (fake data for testing UI without sudo/nmap) |
| `--version` | Show version |
| `--help` | Show help |

### Interactive Controls

When running in interactive mode:

- **Q or ESC** - Quit
- **Ctrl+C** - Stop scanning (or quit if not scanning)
- **↑/↓ Arrow Keys** - Navigate device list
- **Enter** - Toggle detail view
- **E** - Export results (when scan complete)

## How It Works

nscan uses a multi-phase scanning approach:

### Phase 1: Fast Discovery (0-5 seconds)
- Starts tcpdump for passive traffic monitoring
- Executes ARP scan for immediate MAC/IP discovery
- Displays devices instantly as discovered

### Phase 2: Deep Scan (5-30 seconds)
- Runs nmap ping sweep to find live hosts
- Performs detailed nmap scans with OS detection
- Parses service information and open ports
- Updates UI in real-time

### Phase 3: Passive Analysis (continuous in --watch mode)
- Analyzes tcpdump packet capture
- Identifies protocols and services
- Detects hostnames from DHCP/mDNS traffic
- Continuously updates device information

### Data Enrichment

For each discovered device, nscan:

1. **Resolves Manufacturer** - Uses MAC OUI lookup via `oui-data` package
2. **Detects OS** - Analyzes nmap results, services, and hostnames
3. **Infers Device Type** - Classifies based on:
   - Manufacturer patterns
   - Open ports and services
   - Hostname patterns
   - Operating system

## Output Formats

### Interactive (Default)
Beautiful terminal UI with:
- Animated gradient header
- Real-time progress indicators
- Live device list with details
- Color-coded status icons
- Keyboard navigation

### JSON
Structured output with full device details:
```json
{
  "metadata": {
    "timestamp": "2025-01-...",
    "deviceCount": 15
  },
  "devices": [
    {
      "ip": "192.168.1.1",
      "mac": "00:11:22:33:44:55",
      "hostname": "router.local",
      "manufacturer": "Cisco",
      "os": "Linux",
      "usage": "Router/Gateway",
      "ports": [22, 80, 443]
    }
  ]
}
```

### CSV
Tabular format for spreadsheets:
```
IP,MAC,Hostname,Manufacturer,OS,OS Version,Model,Usage,Open Ports,Last Seen
192.168.1.1,00:11:22:33:44:55,router.local,Cisco,Linux,,,"Router/Gateway",22;80;443,2025-01-...
```

### Table
ASCII table for terminal output:
```
+---------------+-------------------+-------------+-------------+--------+----------------+
| IP            | MAC               | Hostname    | Manufacturer| OS     | Usage          |
+---------------+-------------------+-------------+-------------+--------+----------------+
| 192.168.1.1   | 00:11:22:33:44:55 | router      | Cisco       | Linux  | Router/Gateway |
+---------------+-------------------+-------------+-------------+--------+----------------+
```

## Configuration

Create a `.nscancfg.json` file in your home directory for custom defaults:

```json
{
  "timeout": 30,
  "format": "interactive",
  "detectOS": true,
  "fast": false
}
```

## Device Classification

nscan automatically infers device types:

- **Router/Gateway** - Network routers and gateways
- **Switch** - Network switches
- **Access Point** - WiFi access points
- **Server** - Servers and services
- **Computer/Workstation** - Desktop computers
- **Laptop** - Laptop computers
- **Mobile Device** - Phones and tablets
- **IoT Device** - IoT and embedded devices
- **Smart Home Device** - Smart home products
- **Printer/Scanner** - Printing devices
- **TV/Media Device** - TVs and media players
- **Gaming Console** - Gaming systems
- **Storage/NAS** - Network storage
- **Camera/Security** - Security cameras

## Troubleshooting

### Permission Denied
```bash
# Run with sudo
sudo nscan
```

### nmap not found
```bash
# Install nmap
brew install nmap        # macOS
sudo apt install nmap    # Linux
```

### No devices found
- Verify network connectivity
- Check firewall settings
- Try specifying network range manually: `sudo nscan --range 192.168.1.0/24`
- Use verbose mode: `sudo nscan --verbose`

## Development

```bash
# Install dependencies
npm install

# Test the UI without sudo/nmap using demo mode
npm start -- --demo

# Run in development mode (requires sudo for network access)
sudo npm start

# Run with auto-reload
sudo npm run dev
```

### Demo Mode

For development and testing without requiring sudo or nmap:

```bash
# Test the UI with fake data
npm start -- --demo

# Test export functionality
npm start -- --demo --export test.json

# Test different formats
npm start -- --demo --format json
```

Demo mode simulates a network scan with 7 fake devices of various types (router, computer, phone, printer, NAS, TV, IoT device) and goes through all scanning phases with realistic timing.

## Project Structure

```
nscan/
├── src/
│   ├── components/          # Ink React UI components
│   ├── scanners/            # Scanner implementations
│   ├── analyzers/           # Data analysis modules
│   ├── models/              # Data models
│   ├── utils/               # Utility functions
│   ├── cli.js               # CLI entry point
│   └── index.js             # Main coordinator
├── config/
│   └── default-config.json  # Default configuration
├── dist/                    # Built executables
└── package.json
```

## Architecture

- **Scanners** - Modular scanner implementations (ARP, Nmap, Tcpdump)
- **Orchestrator** - Coordinates multiple scanners and manages phases
- **Analyzers** - Enrich device data (manufacturer, OS, usage)
- **Data Aggregator** - Merges data from multiple sources
- **Event Bus** - Decoupled communication between modules
- **Ink UI** - React-based terminal interface

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Security Note

This tool performs network scanning which may be considered intrusive. Always ensure you have permission to scan the networks you're targeting. Use responsibly and ethically.

## Credits

Built with:
- [Ink](https://github.com/vadimdemedes/ink) - React for CLIs
- [Nmap](https://nmap.org/) - Network scanning
- [Commander.js](https://github.com/tj/commander.js) - CLI framework
- [oui-data](https://www.npmjs.com/package/oui-data) - MAC vendor lookup
- [Chalk](https://github.com/chalk/chalk) - Terminal colors
