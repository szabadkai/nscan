/**
 * Demo Mode - Generate fake scan data for testing UI without sudo/nmap
 */

import eventBus, { Events } from './EventBus.js';

/**
 * Demo device templates
 */
const demoDevices = [
  {
    ip: '192.168.1.1',
    mac: '00:11:22:33:44:55',
    hostname: 'router.local',
    manufacturer: 'Cisco Systems',
    os: 'Linux',
    osVersion: '3.10',
    usage: 'Router/Gateway',
    ports: [22, 53, 80, 443],
    services: [
      { port: 22, protocol: 'tcp', state: 'open', service: 'ssh' },
      { port: 80, protocol: 'tcp', state: 'open', service: 'http' },
    ],
  },
  {
    ip: '192.168.1.10',
    mac: 'AA:BB:CC:DD:EE:FF',
    hostname: 'DESKTOP-WIN10',
    manufacturer: 'Intel Corporate',
    os: 'Windows',
    osVersion: '10',
    usage: 'Computer/Workstation',
    ports: [135, 139, 445, 3389],
    services: [
      { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' },
      { port: 3389, protocol: 'tcp', state: 'open', service: 'ms-wbt-server' },
    ],
    workgroup: 'WORKGROUP',
  },
  {
    ip: '192.168.1.15',
    mac: 'BB:CC:DD:EE:FF:00',
    hostname: 'macbook-pro',
    manufacturer: 'Apple',
    os: 'macOS',
    osVersion: '14.1',
    usage: 'Computer/Workstation',
    ports: [22, 88, 445, 5353],
    services: [],
  },
  {
    ip: '192.168.1.25',
    mac: '11:22:33:44:55:66',
    hostname: 'android-phone',
    manufacturer: 'Samsung',
    os: 'Android',
    osVersion: '13',
    usage: 'Mobile Device',
    ports: [],
    services: [],
  },
  {
    ip: '192.168.1.50',
    mac: 'FF:EE:DD:CC:BB:AA',
    hostname: 'hp-printer',
    manufacturer: 'HP',
    os: 'Embedded Linux',
    usage: 'Printer/Scanner',
    ports: [631, 9100],
    services: [
      { port: 631, protocol: 'tcp', state: 'open', service: 'ipp' },
    ],
  },
  {
    ip: '192.168.1.100',
    mac: '12:34:56:78:90:AB',
    hostname: 'nas.local',
    manufacturer: 'Synology',
    os: 'Linux',
    osVersion: '4.4',
    usage: 'Storage/NAS',
    ports: [22, 80, 139, 445, 5000, 5001],
    services: [
      { port: 22, protocol: 'tcp', state: 'open', service: 'ssh' },
      { port: 445, protocol: 'tcp', state: 'open', service: 'microsoft-ds' },
    ],
  },
  {
    ip: '192.168.1.150',
    mac: 'AB:CD:EF:12:34:56',
    hostname: 'smart-tv',
    manufacturer: 'Samsung',
    os: 'Tizen',
    usage: 'TV/Media Device',
    ports: [8001, 8080],
    services: [],
  },
  {
    ip: '192.168.1.200',
    mac: 'DE:AD:BE:EF:CA:FE',
    hostname: 'raspberrypi',
    manufacturer: 'Raspberry Pi Foundation',
    os: 'Linux',
    osVersion: '5.10',
    usage: 'IoT Device',
    ports: [22, 80],
    services: [
      { port: 22, protocol: 'tcp', state: 'open', service: 'ssh' },
    ],
  },
];

/**
 * Demo Scanner - Simulates scanning without actual network access
 */
export class DemoScanner {
  constructor() {
    this.running = false;
    this.devices = [];
  }

  /**
   * Initialize demo scanner (always succeeds)
   */
  async initialize() {
    return {
      ready: true,
      warnings: ['Running in DEMO mode - no actual network scanning'],
      errors: [],
    };
  }

  /**
   * Start demo scan with simulated phases
   */
  async start(config) {
    this.running = true;

    // Emit scan started
    eventBus.emit(Events.SCAN_STARTED, {
      config,
      demo: true,
    });

    // Phase 1: Fast Discovery
    await this._phaseOneDiscovery();

    // Phase 2: Deep Scan
    if (!config.fast) {
      await this._phaseTwoDeepScan();
    }

    // Phase 3: Complete
    this.running = false;
    eventBus.emit(Events.SCAN_COMPLETED, {
      devices: this.devices,
      demo: true,
    });
  }

  /**
   * Phase 1: Fast discovery (simulate ARP scan)
   */
  async _phaseOneDiscovery() {
    eventBus.emit(Events.SCAN_PHASE_CHANGE, {
      phase: 1,
      name: 'Fast Discovery',
    });

    // Discover devices one by one with delay
    for (let i = 0; i < demoDevices.length; i++) {
      await this._delay(500 + Math.random() * 1000);

      const device = {
        ...demoDevices[i],
        // Initially only have basic info
        manufacturer: undefined,
        os: undefined,
        usage: undefined,
        sources: ['demo-arp'],
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        confidence: 30,
      };

      this.devices.push(device);

      eventBus.emit(Events.DEVICE_DISCOVERED, {
        scanner: 'DemoScanner',
        device,
      });
    }
  }

  /**
   * Phase 2: Deep scan (enrich device info)
   */
  async _phaseTwoDeepScan() {
    eventBus.emit(Events.SCAN_PHASE_CHANGE, {
      phase: 2,
      name: 'Deep Scan',
    });

    // Enrich each device with full information
    for (let i = 0; i < this.devices.length; i++) {
      await this._delay(800 + Math.random() * 1200);

      // Update device with full info from template
      this.devices[i] = {
        ...this.devices[i],
        ...demoDevices[i],
        sources: ['demo-arp', 'demo-nmap'],
        lastSeen: new Date().toISOString(),
        confidence: 90,
      };

      eventBus.emit(Events.DEVICE_UPDATED, {
        scanner: 'DemoScanner',
        device: this.devices[i],
      });

      eventBus.emit(Events.DEVICE_ENRICHED, {
        device: this.devices[i],
      });

      // Report progress
      eventBus.emit(Events.SCAN_PROGRESS, {
        scanner: 'DemoScanner',
        scanned: i + 1,
        total: this.devices.length,
      });
    }
  }

  /**
   * Stop demo scan
   */
  async stop() {
    this.running = false;
  }

  /**
   * Get discovered devices
   */
  getDevices() {
    return this.devices;
  }

  /**
   * Get scan stats
   */
  getStats() {
    return {
      running: this.running,
      currentPhase: this.running ? 'scanning' : 'complete',
      deviceCount: this.devices.length,
      scanners: {
        demo: {
          name: 'DemoScanner',
          deviceCount: this.devices.length,
        },
      },
    };
  }

  /**
   * Check if running
   */
  isRunning() {
    return this.running;
  }

  /**
   * Delay helper
   */
  _delay(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
