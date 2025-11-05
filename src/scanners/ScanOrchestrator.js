/**
 * Scan Orchestrator - Coordinates multiple scanners and aggregates results
 */

import ArpScanner from './ArpScanner.js';
import TcpdumpScanner from './TcpdumpScanner.js';
import NmapScanner from './NmapScanner.js';
import eventBus, { Events } from '../utils/EventBus.js';
import {
  checkDependencies,
  getMissingDependencies,
  hasPrivileges,
} from '../utils/CommandRunner.js';
import { detectPrimaryInterface } from '../utils/NetworkUtils.js';

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
      ...options,
    };

    this.scanners = {
      arp: null,
      tcpdump: null,
      nmap: null,
    };

    this.devices = new Map();
    this.running = false;
    this.startTime = null;
    this.currentPhase = null;
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

    if (!deps.nmap) {
      result.errors.push('nmap is required but not found. Please install nmap.');
      result.ready = false;
    }

    if (!deps.tcpdump && !this.options.passive) {
      result.warnings.push(
        'tcpdump not found. Passive monitoring will be disabled.'
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
   * @returns {Promise<void>}
   */
  async start(config = {}) {
    this.running = true;
    this.startTime = Date.now();

    // Emit scan started event
    eventBus.emit(Events.SCAN_STARTED, {
      config,
      options: this.options,
    });

    try {
      // Auto-detect network if not specified
      if (!config.cidr && !config.interface) {
        const primaryIface = detectPrimaryInterface();
        if (primaryIface) {
          config.cidr = primaryIface.cidr;
          config.interface = primaryIface.name;
        } else {
          throw new Error('Could not detect network interface. Please specify manually.');
        }
      }

      // Phase 1: Fast Discovery
      await this._runPhase1(config);

      // Phase 2: Deep Scan (if not in fast mode)
      if (!this.options.fast) {
        await this._runPhase2(config);
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
   * Phase 1: Fast Discovery (ARP + Tcpdump start)
   * @param {Object} config - Scan configuration
   */
  async _runPhase1(config) {
    this.currentPhase = 'fast-discovery';
    eventBus.emit(Events.SCAN_PHASE_CHANGE, { phase: 1, name: 'Fast Discovery' });

    // Start tcpdump in background (if available and not passive-only)
    if (!this.options.passive) {
      try {
        this.scanners.tcpdump = new TcpdumpScanner();
        await this.scanners.tcpdump.start({
          interface: config.interface,
          timeout: 0, // Run indefinitely until stopped
        });
      } catch (error) {
        console.warn('Could not start tcpdump:', error.message);
      }
    }

    // Run ARP scan
    try {
      this.scanners.arp = new ArpScanner();
      await this.scanners.arp.start(config);

      // Merge ARP results
      this._mergeResults(this.scanners.arp.getResults());
    } catch (error) {
      console.warn('ARP scan failed:', error.message);
    }
  }

  /**
   * Phase 2: Deep Scan (Nmap)
   * @param {Object} config - Scan configuration
   */
  async _runPhase2(config) {
    if (this.options.passive) {
      return; // Skip active scanning in passive mode
    }

    this.currentPhase = 'deep-scan';
    eventBus.emit(Events.SCAN_PHASE_CHANGE, { phase: 2, name: 'Deep Scan' });

    try {
      this.scanners.nmap = new NmapScanner();
      await this.scanners.nmap.start({
        cidr: config.cidr,
        detectOS: this.options.detectOS,
        fast: this.options.fast,
        timeout: this.options.timeout,
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

    if (this.scanners.arp?.isRunning()) {
      stopPromises.push(this.scanners.arp.stop());
    }

    if (this.scanners.tcpdump?.isRunning()) {
      stopPromises.push(this.scanners.tcpdump.stop());
    }

    if (this.scanners.nmap?.isRunning()) {
      stopPromises.push(this.scanners.nmap.stop());
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
    for (const device of results) {
      const key = device.ip || device.mac;
      if (!key) continue;

      const existing = this.devices.get(key);

      if (existing) {
        // Merge new data with existing
        // Prefer more detailed/recent information
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
    return {
      ...existing,
      ...update,
      // Prefer non-empty values
      hostname: update.hostname || existing.hostname,
      manufacturer: update.manufacturer || existing.manufacturer,
      os: update.os || existing.os,
      osVersion: update.osVersion || existing.osVersion,
      model: update.model || existing.model,
      // Merge arrays
      ports: [...new Set([...(existing.ports || []), ...(update.ports || [])])],
      services: [...(existing.services || []), ...(update.services || [])],
      // Track sources
      sources: [
        ...new Set([
          ...(existing.sources || [existing.source]),
          update.source,
        ].filter(Boolean)),
      ],
      // Use most recent timestamp
      lastSeen: update.lastSeen || existing.lastSeen,
    };
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

    return {
      running: this.running,
      currentPhase: this.currentPhase,
      deviceCount: this.devices.size,
      duration,
      scanners: {
        arp: this.scanners.arp?.getStats(),
        tcpdump: this.scanners.tcpdump?.getStats(),
        nmap: this.scanners.nmap?.getStats(),
      },
    };
  }

  /**
   * Check if orchestrator is currently running
   * @returns {boolean} True if running
   */
  isRunning() {
    return this.running;
  }
}
