---

**Create a Modern Animated Network Scanner CLI Tool - "nscan"**

**Project Overview:**
Build a professional network scanner CLI application called "nscan" with a modern, animated terminal UI that discovers all devices on a local network and provides comprehensive device information. The tool must compile to a single executable file and use pure ESM syntax throughout.

---

## **Core Requirements**

### **Functionality:**

- Discover all devices on the local network in real-time
- Collect comprehensive device information:
    - IP address
    - MAC address
    - Hostname
    - Operating system (type and version)
    - Manufacturer (from MAC OUI lookup)
    - Device model (when detectable)
    - Plausible usage/device type (inferred from available data)
- Use multiple scanning tools in combination for comprehensive results:
    - `tcpdump` for passive traffic monitoring
    - `nmap` for active scanning and OS detection
    - `arp-scan` or `arp` for MAC address discovery
    - `ping` for connectivity verification
- Display results with live streaming updates as devices are discovered
- Support multiple output formats (interactive UI, JSON, CSV)
- Enable continuous monitoring mode
- Support passive-only scanning mode

### **Technical Stack:**

- Node.js 18+ with ESM modules
- `"type": "module"` in package.json
- All imports must use `.js` file extensions
- Use `import.meta.url` for path resolution (never `__dirname`)
- Compilation target: Single executable using `@yao-pkg/pkg`

### **Dependencies:**

- `ink` v4.4.1+ - React-based terminal UI
- `ink-spinner` - Animated spinners
- `ink-gradient` - Gradient text effects
- `ink-big-text` - Large ASCII text
- `ink-table` - Table rendering
- `ink-text-input` - User input handling
- `react` v18.2.0+ - Required by Ink
- `chalk` v5.3.0+ - Terminal colors
- `gradient-string` - String gradients
- `commander` - CLI argument parsing
- `nanospinner` - Loading spinners
- `cli-boxes` - Box drawing
- `mac-oui-json` - MAC vendor database (OUI lookup)
- `@yao-pkg/pkg` (dev dependency) - Single executable compilation

---

## **Architecture & Structure**

### **Project Structure:**

```
nscan/
├── src/
│   ├── components/          # Ink React components
│   │   ├── App.js
│   │   ├── Header.js
│   │   ├── ScanProgress.js
│   │   ├── DeviceList.js
│   │   ├── DeviceCard.js
│   │   ├── StatusBar.js
│   │   ├── DetailView.js
│   │   └── LoadingSpinner.js
│   ├── scanners/            # Scanner implementations
│   │   ├── BaseScanner.js
│   │   ├── ArpScanner.js
│   │   ├── NmapScanner.js
│   │   ├── TcpdumpScanner.js
│   │   └── ScanOrchestrator.js
│   ├── analyzers/           # Data analysis modules
│   │   ├── OsDetector.js
│   │   ├── ManufacturerResolver.js
│   │   ├── UsageInferrer.js
│   │   └── DataAggregator.js
│   ├── models/              # Data models
│   │   └── Device.js
│   ├── utils/               # Utilities
│   │   ├── paths.js
│   │   ├── NetworkUtils.js
│   │   ├── CommandRunner.js
│   │   ├── EventBus.js
│   │   └── OutputFormatter.js
│   ├── cli.js               # CLI entry point
│   └── index.js             # Main coordinator
├── config/
│   └── default-config.json
├── dist/                    # Build output
├── package.json
└── README.md
```

### **Module Responsibilities:**

**Components (Ink/React):**

- `App.js` - Main application component, orchestrates UI
- `Header.js` - Animated gradient header with branding
- `ScanProgress.js` - Live progress bar with statistics
- `DeviceList.js` - Scrollable list of discovered devices
- `DeviceCard.js` - Individual device display with animations
- `StatusBar.js` - Bottom status bar with controls and tips
- `DetailView.js` - Expanded device detail view
- `LoadingSpinner.js` - Custom loading animations

**Scanners:**

- `BaseScanner.js` - Abstract base class for all scanners, event emitter
- `ArpScanner.js` - Fast MAC/IP discovery using ARP
- `NmapScanner.js` - Detailed scanning with OS detection
- `TcpdumpScanner.js` - Passive network traffic monitoring
- `ScanOrchestrator.js` - Coordinates multiple scanners, aggregates results

**Analyzers:**

- `OsDetector.js` - Parse and identify operating systems from nmap output
- `ManufacturerResolver.js` - Resolve MAC addresses to manufacturers using `mac-oui-json` package
- `UsageInferrer.js` - Infer device purpose from ports, services, hostname, manufacturer
- `DataAggregator.js` - Merge data from multiple sources into unified Device objects

**Models:**

- `Device.js` - Device data model with validation and methods

**Utils:**

- `paths.js` - ESM path utilities, PKG detection, asset path resolution
- `NetworkUtils.js` - CIDR calculations, IP validation, network interface detection
- `CommandRunner.js` - Safe command execution, dependency checking
- `EventBus.js` - Global event bus for cross-module communication
- `OutputFormatter.js` - Format output for JSON, CSV, table views

---

## **User Interface Design**

### **Visual Layout:**

The UI should resemble modern CLI tools like Claude CLI or GitHub Copilot CLI with:

- Animated gradient header with large text branding
- Live updating progress indicators
- Real-time device list that grows as devices are discovered
- Smooth fade-in animations for new devices
- Color-coded status indicators
- Bottom status bar with tips and keyboard shortcuts
- Box borders using Unicode characters
- Responsive layout that adapts to terminal width

### **UI Elements:**

1. **Header Section:**
    - Large gradient text "NSCAN"
    - Animated rainbow or gradient effect
    - Subtitle describing tool purpose
    - Version number

2. **Scan Progress Section:**
    - Animated spinner during active scanning
    - Progress bar with percentage
    - Statistics: devices found, hosts scanned, elapsed time
    - Current scanning phase indicator
    - Box border with rounded corners

3. **Device List Section:**
    - Scrollable list of discovered devices
    - Each device shows: status icon, IP, MAC, hostname
    - Secondary line: usage type, manufacturer, OS
    - Animated spinners for devices being analyzed
    - Green checkmark for completed devices
    - Warning icon for devices with issues
    - Box border with title

4. **Status Bar:**
    - Current activity status
    - Keyboard shortcuts
    - Device count
    - Scan state (scanning/complete)

### **Animations:**

- Spinner types: dots, line, arc, arrows
- Device cards fade in on discovery
- Progress bar smoothly animates
- Status icons transition (spinner → checkmark)
- Gradient title should pulse or shift colors
- Network activity indicator (wave animation)
- Live timestamp updates

### **Color Scheme:**

- Success/Complete: Green
- Active/Scanning: Cyan
- Warning: Yellow
- Error: Red
- Dimmed/Secondary: Gray
- Highlight: Magenta
- Gradients: Rainbow, pastel, or custom

---

## **Scanning Strategy**

### **Phase 1: Fast Discovery (0-5 seconds)**

- Start tcpdump in background for passive monitoring
- Execute `arp-scan -l` or parse `arp -a` for immediate MAC/IP pairs
- Display devices instantly as they're discovered
- Show spinning indicators for each device

### **Phase 2: Deep Scan (5-30 seconds)**

- Run `nmap -sn` ping sweep on network range
- For discovered devices, run detailed `nmap -O -sV --version-light`
- Parse service information and open ports
- Update UI in real-time as enrichment data arrives
- Resolve MAC addresses to manufacturers using `mac-oui-json`

### **Phase 3: Passive Analysis (continuous if --watch)**

- Parse tcpdump capture for traffic patterns
- Identify protocols and services from packet data
- Detect hostname from DHCP, mDNS, NetBIOS traffic
- Update device information dynamically
- Continue monitoring until user stops

### **Data Aggregation:**

- Merge data from all sources into single Device objects
- Handle conflicting information (prefer most detailed source)
- Track data confidence levels
- Timestamp each piece of information
- Support incremental updates

---

## **CLI Interface**

### **Command Structure:**

```
nscan [options]
```

### **Options:**

- `-r, --range <cidr>` - Network range to scan (default: auto-detect)
- `-p, --passive` - Passive mode only (no active probes)
- `-w, --watch` - Continuous monitoring mode
- `-e, --export <file>` - Export results to file (JSON/CSV)
- `-f, --format <type>` - Output format: interactive, json, csv, table
- `-v, --verbose` - Verbose output with debug information
- `-t, --timeout <seconds>` - Scan timeout per host
- `--no-os` - Skip OS detection (faster)
- `--fast` - Fast mode (skip detailed scans)
- `--version` - Show version
- `--help` - Show help

### **Usage Examples:**

```
sudo nscan                           # Interactive mode, auto-detect network
sudo nscan --range 192.168.1.0/24   # Scan specific range
sudo nscan --passive --watch        # Passive monitoring
sudo nscan --export devices.json    # Export and exit
sudo nscan --format json            # JSON output only
sudo nscan --fast                   # Quick scan
```

### **Interactive Controls:**

- Arrow keys: Navigate device list
- Enter: Show detailed device view
- Space: Pause/resume scanning
- E: Export results
- R: Refresh/rescan
- F: Toggle filter view
- Q or Ctrl+C: Quit

---

## **Manufacturer Resolution (mac-oui-json)**

### **Integration Requirements:**

- Use `mac-oui-json` npm package for MAC vendor lookups
- No bundled JSON files needed (package handles database)
- Implement efficient lookup caching
- Handle malformed MAC addresses gracefully
- Support both full MAC and OUI-only lookups
- Display "Unknown" for unresolved vendors

### **ManufacturerResolver Module:**

- Import and use `mac-oui-json` package
- Normalize MAC address formats before lookup
- Cache results to avoid repeated lookups
- Handle edge cases: local addresses, invalid MACs
- Support bulk lookups for performance
- Provide manufacturer name with confidence level

---

## **Device Usage Inference**

### **Inference Logic:**

Determine device type/usage based on:

1. **Manufacturer patterns:**
    - Apple → Mobile, Computer, or IoT
    - Cisco/Juniper → Network Equipment
    - Raspberry Pi → IoT/Server
    - HP/Dell/Lenovo → Computer/Server
    - Samsung/LG → TV, Mobile, or Appliance

2. **Open ports/services:**
    - 22 (SSH), 80/443 (HTTP/S) → Server
    - 445 (SMB), 3389 (RDP) → Computer
    - 8080, 8443 → Application Server
    - 3306, 5432 → Database Server
    - 1883 (MQTT), 8883 → IoT Device
    - 5353 (mDNS) → Apple Device

3. **Hostname patterns:**
    - iPhone, iPad, android → Mobile
    - ESP, arduino, pi → IoT
    - desktop, laptop, PC → Computer
    - router, switch, AP → Network Equipment
    - printer, scanner → Peripheral

4. **Operating system:**
    - iOS, Android → Mobile
    - Windows, macOS, Linux → Computer
    - OpenWrt, DD-WRT → Router
    - Embedded Linux → IoT

### **Usage Categories:**

- Router/Gateway
- Switch
- Access Point
- Server
- Computer/Workstation
- Laptop
- Mobile Device
- IoT Device
- Smart Home Device
- Printer/Scanner
- TV/Media Device
- Gaming Console
- Storage/NAS
- Camera/Security
- Unknown

---

## **Single Executable Compilation**

### **PKG Configuration:**

- Use `@yao-pkg/pkg` for compilation
- Target platforms: Linux x64, macOS x64/ARM64, Windows x64
- Enable GZip compression for smaller binaries
- Bundle all required scripts and assets
- No external dependencies at runtime
- Node.js runtime included in executable

### **Build Targets:**

- `node18-linux-x64` → nscan-linux
- `node18-macos-x64` → nscan-macos-intel
- `node18-macos-arm64` → nscan-macos-arm
- `node18-win-x64` → nscan-win.exe

### **PKG Compatibility:**

- All imports must be static (no dynamic requires)
- Use proper path resolution for PKG environment
- Detect PKG runtime: `typeof process.pkg !== 'undefined'`
- Handle asset paths differently in PKG vs development
- Test both development and compiled versions
- No native addons or binary dependencies

### **Build Scripts:**

- `npm start` - Development mode
- `npm run dev` - Watch mode
- `npm run build` - Build all platforms
- `npm run build:linux` - Build Linux only
- `npm run build:macos` - Build macOS only
- `npm run build:win` - Build Windows only

### **Distribution:**

- Single executable file per platform
- No installation required
- Copy to system PATH for global access
- Target size: < 50MB with compression
- Self-contained (no external dependencies)
- Works offline (MAC database included via npm package)

---

## **Error Handling & Validation**

### **Privilege Checking:**

- Detect if running as root/sudo
- Display helpful error message if insufficient privileges
- Suggest correct command: `sudo nscan`
- Exit gracefully with appropriate exit code

### **Dependency Validation:**

- Check for required system tools on startup
- Required: nmap, tcpdump, arp-scan or arp
- Display missing tools with installation instructions
- Support graceful degradation (work without some tools)
- Show warnings for missing optional tools

### **Network Validation:**

- Validate CIDR notation
- Auto-detect network interface if not specified
- Handle multiple network interfaces
- Detect VPN/tunnel interfaces
- Warn about unusual network configurations

### **Error Display:**

- Show errors inline in UI with colored warnings
- Don't crash on individual device scan failures
- Log verbose errors in debug mode
- Provide actionable error messages
- Graceful shutdown on fatal errors

---

## **Performance Considerations**

### **Optimization:**

- Run multiple scanners in parallel where possible
- Throttle UI updates to max 60 FPS
- Cache manufacturer lookups
- Use efficient data structures (Map instead of Array for lookups)
- Stream command output instead of buffering
- Debounce rapid device updates
- Implement scan timeouts to prevent hangs

### **Resource Management:**

- Limit concurrent nmap processes
- Clean up child processes on exit
- Handle SIGINT/SIGTERM gracefully
- Close tcpdump properly
- Release file handles
- Clear intervals and timeouts

---

## **Code Quality Standards**

### **ESM Requirements:**

- Use `import/export` syntax exclusively
- Include `.js` extensions on all relative imports
- Use `import.meta.url` for file path resolution
- Top-level await is allowed
- Never use `require()` or `module.exports`
- Use dynamic imports only for optional features

### **Documentation:**

- JSDoc comments for all public functions and classes
- Explain complex algorithms
- Document expected input/output formats
- Include usage examples in comments
- README with comprehensive documentation

### **Code Style:**

- Modern ES6+ features (destructuring, spread, async/await)
- Consistent naming conventions
- Single responsibility principle
- DRY (Don't Repeat Yourself)
- Clear separation of concerns
- Prettier formatting (80 character line width)

### **Testing Considerations:**

- Structure code for testability
- Separate business logic from UI
- Mock system commands for testing
- Validate parser functions independently
- Test both PKG and development modes

---

## **Configuration**

### **Config File Support:**

- Support `.nscancfg.json` in home directory
- Allow command-line overrides
- Default configuration bundled
- Schema: network ranges, timeouts, display preferences
- Validate configuration on load

### **Configurable Options:**

- Default network range
- Scan timeouts
- UI colors/theme
- Output format preferences
- Tool paths (for non-standard installations)
- Passive mode settings
- Export location

---

## **Output Formats**

### **Interactive (Default):**

- Full animated Ink UI
- Real-time updates
- Interactive controls

### **JSON:**

- Structured device data
- Timestamps included
- Metadata about scan
- Easy to parse programmatically

### **CSV:**

- Tabular format
- Headers: IP, MAC, Hostname, OS, Manufacturer, Model, Usage
- Importable to spreadsheets

### **Table:**

- Static ASCII table
- Non-interactive
- Suitable for scripting
- Clean terminal output

---

## **Development Workflow**

### **Initial Setup:**

1. Initialize npm project with ESM support
2. Install all dependencies
3. Create project structure
4. Set up PKG configuration
5. Create path utilities for ESM/PKG compatibility

### **Development Order:**

1. Build path utilities and command runner
2. Implement individual scanners with parsing logic
3. Create ManufacturerResolver using mac-oui-json
4. Build device model and aggregator
5. Implement ScanOrchestrator
6. Create Ink UI components
7. Wire everything together in App component
8. Build CLI entry point
9. Test in development mode
10. Compile and test executables

### **Testing:**

- Test each scanner independently
- Verify MAC lookup functionality
- Test UI rendering and animations
- Test on different network configurations
- Test compiled executables on target platforms
- Verify privilege checking works
- Test graceful error handling

---

## **Distribution & Installation**

### **Post-Build:**

- Executables in `dist/` directory
- Include README in dist
- Create installation script
- Generate SHA256 checksums

### **Installation Instructions:**

```
# Linux/macOS
sudo cp nscan-linux /usr/local/bin/nscan
sudo chmod +x /usr/local/bin/nscan

# Windows
# Copy nscan-win.exe to a directory in PATH
```

### **Usage After Installation:**

Users can run `sudo nscan` from anywhere on the system without node or npm installed.

---

## **Future Extensibility**

### **Plugin Architecture Considerations:**

- Design scanners as pluggable modules
- Use event-driven architecture for loose coupling
- Allow easy addition of new scanner types
- Support custom device type inference rules
- Enable theme/color customization

### **Potential Features:**

- Historical tracking of devices
- Alert on new devices
- Integration with network management tools
- Export to various formats (XML, YAML)
- REST API mode
- Web dashboard
- Device grouping and tagging
- Network topology visualization

---

This specification provides comprehensive requirements for building nscan. The tool should feel modern, professional, and fast while providing detailed network visibility.
