/**
 * Scan Orchestrator - Coordinates multiple scanners and aggregates results
 * Enhanced with mDNS, SSDP, NDP (IPv6), and scan level support
 */

import ArpScanner from './ArpScanner.js';
import NdpScanner from './NdpScanner.js';
import TcpdumpScanner from './TcpdumpScanner.js';
import NmapScanner from './NmapScanner.js';
import MdnsScanner from './MdnsScanner.js';
import SsdpScanner from './SsdpScanner.js';
import NetbiosBrowserScanner from './NetbiosBrowserScanner.js';
import NetbiosResolver from '../analyzers/NetbiosResolver.js';
import eventBus, { Events } from '../utils/EventBus.js';
import {
  checkDependencies,
  getMissingDependencies,
  hasPrivileges,
} from '../utils/CommandRunner.js';
import { 
  detectPrimaryInterface, 
  detectPrimaryInterfaceWithIPv6,
  getActiveInterfacesWithIPv6,
} from '../utils/NetworkUtils.js';

/**
 * Scan level configurations
 */
const SCAN_LEVEL_CONFIG = {
  quick: {
    enableMdns: true,
    enableSsdp: true,
    enableNmap: false,
    enableTcpdump: false,
    timeout: 5,
  },
  standard: {
    enableMdns: true,
    enableSsdp: true,
    enableNmap: true,
    enableTcpdump: true,
    timeout: 30,
  },
  thorough: {
    enableMdns: true,
    enableSsdp: true,
    enableNmap: true,
    enableTcpdump: true,
    timeout: 90,
  },
};

/**
 * Orchestrates multiple scanners to perform comprehensive network discovery
 * Manages scanning phases and aggregates results from all sources
 */
export default class ScanOrchestrator {
  /**
   * Create scan orchestrator
   * @param {Object} options - Orchestrator options
   */
  constructor(options = {}) {
    this.options = {
      passive: false,
      fast: false,
      detectOS: true,
      watch: false,
      timeout: 30,
      scanLevel: 'standard',
      ipv6: true,
      ...options,
    };

    // Adjust scan level for fast mode
    if (this.options.fast) {
      this.options.scanLevel = 'quick';
    }

    this.scanners = {
      arp: null,
      ndp: null,
      tcpdump: null,
      nmap: null,
      netbios: null,
      netbiosBrowser: null,
      mdns: null,
      ssdp: null,
    };

    this.devices = new Map();
    this.running = false;
    this.startTime = null;
    this.currentPhase = null;
    
    // Track discovered IPv6 addresses for deep scanning
    this.discoveredIPv6 = [];
  }

  /**
   * Initialize and validate environment
   * @returns {Promise<Object>} Validation result with warnings
   */
  async initialize() {
    const result = {
      ready: true,
      warnings: [],
      errors: [],
    };

    // Check privileges
    if (!hasPrivileges()) {
      result.ready = false;
      result.errors.push(
        'Insufficient privileges. Please run with sudo/administrator rights.'
      );
      return result;
    }

    // Check dependencies
    const deps = await checkDependencies();
    const missing = getMissingDependencies(deps);

    if (!deps.nmap && this.options.scanLevel !== 'quick') {
      result.errors.push('nmap is required but not found. Please install nmap.');
      result.ready = false;
    }

    if (!deps.tcpdump && !this.options.passive) {
      result.warnings.push(
        'tcpdump not found. Passive monitoring and DHCP hostname discovery will be disabled.'
      );
    }

    if (!deps['arp-scan'] && !deps.arp) {
      result.warnings.push('Neither arp-scan nor arp found. ARP discovery may be limited.');
    }

    // Add installation instructions for missing deps
    if (missing.length > 0) {
      result.missing = missing;
    }

    return result;
  }

  /**
   * Start comprehensive network scan
   * @param {Object} config - Scan configuration
   * @param {string} config.cidr - CIDR range (auto-detected if not provided)
   * @param {string} config.interface - Network interface
   * @param {string} config.scanLevel - Scan level (quick/standard/thorough)
   * @param {boolean} config.ipv6 - Enable IPv6 scanning
   * @returns {Promise<void>}
   */
  async start(config = {}) {
    this.running = true;
    this.startTime = Date.now();

    // Merge scan level config
    const levelConfig = SCAN_LEVEL_CONFIG[this.options.scanLevel] || SCAN_LEVEL_CONFIG.standard;

    // Emit scan started event
    eventBus.emit(Events.SCAN_STARTED, {
      config,
      options: this.options,
      scanLevel: this.options.scanLevel,
    });

    try {
      // Auto-detect network if not specified
      if (!config.cidr && !config.interface) {
        const primaryIface = this.options.ipv6 
          ? detectPrimaryInterfaceWithIPv6()
          : detectPrimaryInterface();
          
        if (primaryIface) {
          config.cidr = primaryIface.ipv4Cidr || primaryIface.cidr;
          config.interface = primaryIface.name;
          
          // Store IPv6 info for later
          if (primaryIface.ipv6?.length > 0) {
            config.hasIPv6 = true;
          }
        } else {
          throw new Error('Could not detect network interface. Please specify manually.');
        }
      }

      // Phase 0: Passive Discovery (mDNS, SSDP) - runs in parallel
      if (levelConfig.enableMdns || levelConfig.enableSsdp) {
        await this._runPhase0(config, levelConfig);
      }

      // Phase 1: Fast Discovery (ARP + NDP + tcpdump start)
      await this._runPhase1(config, levelConfig);

      // Phase 2: Deep Scan (if not in quick mode)
      if (levelConfig.enableNmap && !this.options.passive) {
        await this._runPhase2(config, levelConfig);
      }

      // Phase 3: Passive Monitoring (if watch mode)
      if (this.options.watch) {
        await this._runPhase3(config);
      }

      // Emit completion
      if (!this.options.watch) {
        this.running = false;
        eventBus.emit(Events.SCAN_COMPLETED, {
          devices: this.getDevices(),
          stats: this.getStats(),
        });
      }
    } catch (error) {
      this.running = false;
      eventBus.emit(Events.SCAN_ERROR, { error: error.message });
      throw error;
    }
  }

  /**
   * Phase 0: Passive Discovery (mDNS, SSDP)
   * These run without active probing and can discover smart devices
   * @param {Object} config - Scan configuration
   * @param {Object} levelConfig - Scan level configuration
   */
  async _runPhase0(config, levelConfig) {
    this.currentPhase = 'passive-discovery';
    eventBus.emit(Events.SCAN_PHASE_CHANGE, { phase: 0, name: 'Passive Discovery' });

    const discoveryPromises = [];

    // mDNS/Bonjour discovery
    if (levelConfig.enableMdns) {
      discoveryPromises.push(
        (async () => {
          try {
            this.scanners.mdns = new MdnsScanner();
            await this.scanners.mdns.start({
              timeout: Math.min(levelConfig.timeout * 1000, 10000),
            });
            this._mergeResults(this.scanners.mdns.getResults());
            eventBus.emit(Events.SCAN_PROGRESS, {
              phase: 'mdns',
              message: `mDNS: Found ${this.scanners.mdns.devices.size} devices`,
            });
          } catch (error) {
            console.warn('mDNS discovery failed:', error.message);
          }
        })()
      );
    }

    // SSDP/UPnP discovery
    if (levelConfig.enableSsdp) {
      discoveryPromises.push(
        (async () => {
          try {
            this.scanners.ssdp = new SsdpScanner();
            await this.scanners.ssdp.start({
              timeout: Math.min(levelConfig.timeout * 1000, 5000),
              ipv6: this.options.ipv6,
            });
            this._mergeResults(this.scanners.ssdp.getResults());
            eventBus.emit(Events.SCAN_PROGRESS, {
              phase: 'ssdp',
              message: `SSDP: Found ${this.scanners.ssdp.devices.size} devices`,
            });
          } catch (error) {
            console.warn('SSDP discovery failed:', error.message);
          }
        })()
      );
    }

    // Wait for all passive discovery to complete
    await Promise.allSettled(discoveryPromises);
  }

  /**
   * Phase 1: Fast Discovery (ARP + NDP + Tcpdump start)
   * @param {Object} config - Scan configuration
   * @param {Object} levelConfig - Scan level configuration
   */
  async _runPhase1(config, levelConfig) {
    this.currentPhase = 'fast-discovery';
    eventBus.emit(Events.SCAN_PHASE_CHANGE, { phase: 1, name: 'Fast Discovery' });

    // Start tcpdump in background (if available and enabled)
    if (levelConfig.enableTcpdump && !this.options.passive) {
      try {
        this.scanners.tcpdump = new TcpdumpScanner();
        await this.scanners.tcpdump.start({
          interface: config.interface,
          timeout: 0, // Run indefinitely until stopped
          captureIPv6: this.options.ipv6,
          captureDHCP: true,
        });
      } catch (error) {
        console.warn('Could not start tcpdump:', error.message);
      }
    }

    // Run ARP and NDP scans in parallel
    const scanPromises = [];

    // ARP scan (IPv4)
    scanPromises.push(
      (async () => {
        try {
          this.scanners.arp = new ArpScanner();
          await this.scanners.arp.start(config);
          this._mergeResults(this.scanners.arp.getResults());
        } catch (error) {
          console.warn('ARP scan failed:', error.message);
        }
      })()
    );

    // NDP scan (IPv6) if enabled
    if (this.options.ipv6) {
      scanPromises.push(
        (async () => {
          try {
            this.scanners.ndp = new NdpScanner();
            await this.scanners.ndp.start({ interface: config.interface });
            const ndpResults = this.scanners.ndp.getResults();
            this._mergeResults(ndpResults);
            
            // Collect IPv6 addresses for potential deep scanning
            for (const device of ndpResults) {
              if (device.ipv6) {
                for (const v6 of device.ipv6) {
                  const addr = typeof v6 === 'string' ? v6 : v6.address;
                  if (!this.discoveredIPv6.includes(addr)) {
                    this.discoveredIPv6.push(addr);
                  }
                }
              }
            }
          } catch (error) {
            console.warn('NDP scan failed:', error.message);
          }
        })()
      );
    }

    await Promise.allSettled(scanPromises);

    // Discover Windows machines via NetBIOS broadcast lookups
    await this._runNetbiosBrowserScan();

    // Run fast NetBIOS hostname resolution on discovered IPs
    await this._runNetbiosResolution();
  }

  /**
   * Discover Windows machines via NetBIOS name service
   * Uses broadcast-based discovery similar to Finder's Network browser
   */
  async _runNetbiosBrowserScan() {
    try {
      eventBus.emit(Events.SCAN_PROGRESS, {
        phase: 'netbios-browser',
        message: 'Discovering Windows machines via NetBIOS...',
      });

      this.scanners.netbiosBrowser = new NetbiosBrowserScanner();
      await this.scanners.netbiosBrowser.start({ timeout: 8000 });

      // Merge discovered Windows machines
      const results = this.scanners.netbiosBrowser.getResults();
      this._mergeResults(results);

      if (results.length > 0) {
        eventBus.emit(Events.SCAN_PROGRESS, {
          phase: 'netbios-browser',
          message: `NetBIOS: Found ${results.length} Windows machines`,
        });
      }
    } catch (error) {
      console.warn('NetBIOS browser scan failed:', error.message);
    }
  }

  /**
   * Run fast NetBIOS hostname resolution on all discovered devices
   * This provides Windows hostnames in Phase 1 (within seconds)
   */
  async _runNetbiosResolution() {
    // Get IPs of devices without hostnames
    const ipsToResolve = [];
    for (const device of this.devices.values()) {
      const ip = device.ip || device.ipv4;
      if (ip && !device.hostname) {
        ipsToResolve.push(ip);
      }
    }

    if (ipsToResolve.length === 0) {
      return;
    }

    try {
      this.scanners.netbios = new NetbiosResolver();
      const available = await this.scanners.netbios.checkAvailability();

      if (!available) {
        // NetBIOS tools not available, skip silently
        return;
      }

      eventBus.emit(Events.SCAN_PROGRESS, {
        phase: 'netbios-resolution',
        message: `Resolving Windows hostnames for ${ipsToResolve.length} devices...`,
      });

      // Resolve in parallel with 3 second timeout per host
      const results = await this.scanners.netbios.resolveMany(ipsToResolve, 3000, 10);

      // Merge results into devices
      for (const [ip, info] of results) {
        const existing = this.devices.get(ip);
        if (existing && info.hostname) {
          const updated = {
            ...existing,
            hostname: info.hostname,
            workgroup: info.workgroup || existing.workgroup,
            sources: [...new Set([...(existing.sources || [existing.source]), info.source])],
          };
          this.devices.set(ip, updated);
          eventBus.emit(Events.DEVICE_UPDATED, updated);
        }
      }

      if (results.size > 0) {
        eventBus.emit(Events.SCAN_PROGRESS, {
          phase: 'netbios-resolution',
          message: `Resolved ${results.size} Windows hostnames`,
        });
      }
    } catch (error) {
      console.warn('NetBIOS resolution failed:', error.message);
    }
  }

  /**
   * Phase 2: Deep Scan (Nmap)
   * @param {Object} config - Scan configuration
   * @param {Object} levelConfig - Scan level configuration
   */
  async _runPhase2(config, levelConfig) {
    if (this.options.passive) {
      return; // Skip active scanning in passive mode
    }

    this.currentPhase = 'deep-scan';
    eventBus.emit(Events.SCAN_PHASE_CHANGE, { phase: 2, name: 'Deep Scan' });

    try {
      this.scanners.nmap = new NmapScanner({ scanLevel: this.options.scanLevel });
      await this.scanners.nmap.start({
        cidr: config.cidr,
        detectOS: this.options.detectOS,
        fast: this.options.scanLevel === 'quick',
        timeout: levelConfig.timeout,
        scanLevel: this.options.scanLevel,
        interface: config.interface,
        ipv6Targets: this.options.ipv6 ? this.discoveredIPv6 : [],
      });

      // Merge nmap results
      this._mergeResults(this.scanners.nmap.getResults());
    } catch (error) {
      console.warn('Nmap scan failed:', error.message);
    }
  }

  /**
   * Phase 3: Passive Monitoring (continuous)
   * @param {Object} config - Scan configuration
   */
  async _runPhase3(config) {
    this.currentPhase = 'passive-monitoring';
    eventBus.emit(Events.SCAN_PHASE_CHANGE, { phase: 3, name: 'Passive Monitoring' });

    // Tcpdump should already be running from Phase 1
    // Just keep it running until stop() is called

    // Set up periodic result merging
    this.monitorInterval = setInterval(() => {
      if (this.scanners.tcpdump) {
        this._mergeResults(this.scanners.tcpdump.getResults());
      }
    }, 5000); // Merge every 5 seconds
  }

  /**
   * Stop all scanners
   */
  async stop() {
    this.running = false;

    // Clear monitor interval
    if (this.monitorInterval) {
      clearInterval(this.monitorInterval);
      this.monitorInterval = null;
    }

    // Stop all scanners
    const stopPromises = [];

    for (const [name, scanner] of Object.entries(this.scanners)) {
      if (scanner?.isRunning?.()) {
        stopPromises.push(scanner.stop().catch(() => {}));
      }
    }

    await Promise.allSettled(stopPromises);

    // Final merge of all results
    this._mergeAllResults();

    // Emit completion
    eventBus.emit(Events.SCAN_COMPLETED, {
      devices: this.getDevices(),
      stats: this.getStats(),
    });
  }

  /**
   * Merge results from a scanner into the device map
   * @param {Array<Object>} results - Scanner results
   */
  _mergeResults(results) {
    if (!results || !Array.isArray(results)) return;
    
    for (const device of results) {
      // Skip null/undefined devices
      if (!device) continue;
      
      // Prefer MAC-based keying for dual-stack correlation
      const key = device.mac || device.ip || device.ipv4 || 
        (device.ipv6?.[0]?.address) || (device.ipv6?.[0]);
      if (!key) continue;

      const existing = this.devices.get(key);

      if (existing) {
        // Merge new data with existing
        this.devices.set(key, this._mergeDevice(existing, device));
        eventBus.emit(Events.DEVICE_UPDATED, this.devices.get(key));
      } else {
        // New device
        this.devices.set(key, device);
        eventBus.emit(Events.DEVICE_DISCOVERED, device);
      }
    }
  }

  /**
   * Merge all scanner results
   */
  _mergeAllResults() {
    for (const scanner of Object.values(this.scanners)) {
      if (scanner) {
        this._mergeResults(scanner.getResults());
      }
    }
  }

  /**
   * Merge two device objects, preferring more detailed information
   * @param {Object} existing - Existing device data
   * @param {Object} update - New device data
   * @returns {Object} Merged device
   */
  _mergeDevice(existing, update) {
    const merged = {
      ...existing,
      ...update,
      // Prefer non-empty values
      ip: update.ip || existing.ip,
      ipv4: update.ipv4 || update.ip || existing.ipv4,
      mac: update.mac || existing.mac,
      hostname: update.hostname || existing.hostname,
      manufacturer: update.manufacturer || existing.manufacturer,
      os: update.os || existing.os,
      osVersion: update.osVersion || existing.osVersion,
      model: update.model || existing.model,
      workgroup: update.workgroup || existing.workgroup,
      fqdn: update.fqdn || existing.fqdn,
      // Merge arrays
      ports: [...new Set([...(existing.ports || []), ...(update.ports || [])])],
      services: [...(existing.services || []), ...(update.services || [])],
      // Track sources
      sources: [
        ...new Set([
          ...(existing.sources || [existing.source]),
          ...(update.sources || [update.source]),
        ].filter(Boolean)),
      ],
      discoveredVia: [
        ...new Set([
          ...(existing.discoveredVia || []),
          ...(update.discoveredVia || []),
        ].filter(Boolean)),
      ],
      // Use most recent timestamp
      lastSeen: update.lastSeen || existing.lastSeen,
    };

    // Merge IPv6 addresses
    merged.ipv6 = this._mergeIPv6Arrays(existing.ipv6, update.ipv6);

    return merged;
  }

  /**
   * Merge two IPv6 address arrays
   * @param {Array} existing - Existing IPv6 addresses
   * @param {Array} update - New IPv6 addresses
   * @returns {Array} Merged IPv6 addresses
   */
  _mergeIPv6Arrays(existing, update) {
    if (!existing && !update) return [];
    if (!existing) return update;
    if (!update) return existing;

    const merged = [...existing];
    
    for (const newAddr of update) {
      const addr = typeof newAddr === 'string' ? newAddr : newAddr.address;
      const exists = merged.some(e => 
        (typeof e === 'string' ? e : e.address) === addr
      );
      if (!exists) {
        merged.push(newAddr);
      }
    }

    return merged;
  }

  /**
   * Get all discovered devices
   * @returns {Array<Object>} Array of devices
   */
  getDevices() {
    return Array.from(this.devices.values());
  }

  /**
   * Get scan statistics
   * @returns {Object} Statistics
   */
  getStats() {
    const duration = this.startTime ? (Date.now() - this.startTime) / 1000 : 0;

    const stats = {
      running: this.running,
      currentPhase: this.currentPhase,
      scanLevel: this.options.scanLevel,
      deviceCount: this.devices.size,
      duration,
      ipv6Enabled: this.options.ipv6,
      discoveredIPv6Count: this.discoveredIPv6.length,
      scanners: {},
    };

    // Add scanner stats
    for (const [name, scanner] of Object.entries(this.scanners)) {
      if (scanner) {
        stats.scanners[name] = scanner.getStats?.() || { deviceCount: scanner.devices?.size || 0 };
      }
    }

    return stats;
  }

  /**
   * Check if orchestrator is currently running
   * @returns {boolean} True if running
   */
  isRunning() {
    return this.running;
  }
}
