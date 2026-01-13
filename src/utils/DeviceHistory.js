/**
 * Device History - Tracks device appearance/disappearance over time
 * Provides persistence and historical tracking of discovered devices
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Default history configuration
 */
const DEFAULT_CONFIG = {
  retentionDays: 30,
  historyFile: path.join(os.homedir(), '.nscan', 'device-history.json'),
  autoSave: true,
  autoSaveInterval: 60000, // 1 minute
};

/**
 * Device history entry structure
 * @typedef {Object} DeviceHistoryEntry
 * @property {string} mac - Device MAC address (primary key)
 * @property {string} ipv4 - Last known IPv4 address
 * @property {Array<Object>} ipv6 - Last known IPv6 addresses
 * @property {string} hostname - Device hostname
 * @property {string} manufacturer - Device manufacturer
 * @property {string} os - Device operating system
 * @property {number} firstSeen - Unix timestamp when first seen
 * @property {number} lastSeen - Unix timestamp when last seen
 * @property {number} seenCount - Number of times seen in scans
 * @property {Array<string>} ipHistory - History of IP addresses used
 * @property {Array<string>} hostnameHistory - History of hostnames used
 * @property {boolean} isActive - Whether device was seen in last scan
 */

/**
 * Manages device history for tracking network devices over time
 */
export default class DeviceHistory {
  /**
   * Create device history manager
   * @param {Object} config - History configuration
   */
  constructor(config = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.devices = new Map(); // MAC -> DeviceHistoryEntry
    this.ipIndex = new Map(); // IP -> MAC (for quick lookup)
    this.loaded = false;
    this.dirty = false;
    this.autoSaveTimer = null;
  }

  /**
   * Initialize history - load from disk
   * @returns {Promise<void>}
   */
  async initialize() {
    await this.load();
    
    // Start auto-save timer
    if (this.config.autoSave) {
      this.autoSaveTimer = setInterval(() => {
        if (this.dirty) {
          this.save().catch(() => {});
        }
      }, this.config.autoSaveInterval);
    }
  }

  /**
   * Clean up resources
   */
  async cleanup() {
    if (this.autoSaveTimer) {
      clearInterval(this.autoSaveTimer);
      this.autoSaveTimer = null;
    }
    
    if (this.dirty) {
      await this.save();
    }
  }

  /**
   * Load history from disk
   * @returns {Promise<void>}
   */
  async load() {
    try {
      if (!fs.existsSync(this.config.historyFile)) {
        this.loaded = true;
        return;
      }

      const data = await fs.promises.readFile(this.config.historyFile, 'utf-8');
      const history = JSON.parse(data);

      // Convert array to Map
      if (Array.isArray(history.devices)) {
        for (const device of history.devices) {
          if (device.mac) {
            this.devices.set(device.mac.toLowerCase(), device);
            this._indexDevice(device);
          }
        }
      }

      // Prune old entries
      this._pruneOldEntries();

      this.loaded = true;
    } catch (error) {
      console.warn('Could not load device history:', error.message);
      this.loaded = true;
    }
  }

  /**
   * Save history to disk
   * @returns {Promise<void>}
   */
  async save() {
    try {
      // Ensure directory exists
      const dir = path.dirname(this.config.historyFile);
      if (!fs.existsSync(dir)) {
        await fs.promises.mkdir(dir, { recursive: true });
      }

      const history = {
        version: 1,
        savedAt: Date.now(),
        deviceCount: this.devices.size,
        devices: Array.from(this.devices.values()),
      };

      await fs.promises.writeFile(
        this.config.historyFile,
        JSON.stringify(history, null, 2),
        'utf-8'
      );

      this.dirty = false;
    } catch (error) {
      console.error('Could not save device history:', error.message);
      throw error;
    }
  }

  /**
   * Update history with current scan results
   * @param {Array<Object>} devices - Devices from current scan
   * @returns {Object} Summary of changes
   */
  updateFromScan(devices) {
    const now = Date.now();
    const summary = {
      newDevices: [],
      returnedDevices: [], // Devices that reappeared after being offline
      changedDevices: [], // Devices with changed IP/hostname
      activeCount: 0,
    };

    // Mark all existing devices as inactive for this scan
    const seenMacs = new Set();

    for (const device of devices) {
      const mac = device.mac?.toLowerCase();
      if (!mac) continue;

      seenMacs.add(mac);
      summary.activeCount++;

      const existing = this.devices.get(mac);

      if (existing) {
        // Device seen before
        const wasActive = existing.isActive;
        const changes = this._detectChanges(existing, device);

        // Update entry
        existing.lastSeen = now;
        existing.seenCount++;
        existing.isActive = true;
        existing.ipv4 = device.ipv4 || device.ip || existing.ipv4;
        existing.ipv6 = device.ipv6 || existing.ipv6;
        existing.hostname = device.hostname || existing.hostname;
        existing.manufacturer = device.manufacturer || existing.manufacturer;
        existing.os = device.os || existing.os;
        existing.model = device.model || existing.model;

        // Track IP/hostname history
        this._addToHistory(existing, 'ipHistory', device.ipv4 || device.ip);
        this._addToHistory(existing, 'hostnameHistory', device.hostname);

        this._indexDevice(existing);

        if (!wasActive) {
          summary.returnedDevices.push({
            mac,
            hostname: existing.hostname,
            lastSeen: existing.lastSeen,
            offlineDuration: now - (existing.lastSeen || existing.firstSeen),
          });
        }

        if (changes.length > 0) {
          summary.changedDevices.push({
            mac,
            hostname: existing.hostname,
            changes,
          });
        }
      } else {
        // New device
        const entry = {
          mac,
          ipv4: device.ipv4 || device.ip,
          ipv6: device.ipv6 || [],
          hostname: device.hostname,
          manufacturer: device.manufacturer,
          os: device.os,
          model: device.model,
          firstSeen: now,
          lastSeen: now,
          seenCount: 1,
          ipHistory: [],
          hostnameHistory: [],
          isActive: true,
        };

        this._addToHistory(entry, 'ipHistory', device.ipv4 || device.ip);
        this._addToHistory(entry, 'hostnameHistory', device.hostname);

        this.devices.set(mac, entry);
        this._indexDevice(entry);

        summary.newDevices.push({
          mac,
          hostname: device.hostname,
          ip: device.ipv4 || device.ip,
          manufacturer: device.manufacturer,
        });
      }
    }

    // Mark devices not in this scan as inactive
    for (const [mac, entry] of this.devices) {
      if (!seenMacs.has(mac)) {
        entry.isActive = false;
      }
    }

    this.dirty = true;
    return summary;
  }

  /**
   * Detect changes between existing and new device data
   * @param {Object} existing - Existing device entry
   * @param {Object} newDevice - New device data
   * @returns {Array<Object>} List of changes
   */
  _detectChanges(existing, newDevice) {
    const changes = [];
    const newIP = newDevice.ipv4 || newDevice.ip;

    if (newIP && existing.ipv4 && newIP !== existing.ipv4) {
      changes.push({
        field: 'ipv4',
        from: existing.ipv4,
        to: newIP,
      });
    }

    if (newDevice.hostname && existing.hostname && 
        newDevice.hostname !== existing.hostname) {
      changes.push({
        field: 'hostname',
        from: existing.hostname,
        to: newDevice.hostname,
      });
    }

    if (newDevice.os && existing.os && newDevice.os !== existing.os) {
      changes.push({
        field: 'os',
        from: existing.os,
        to: newDevice.os,
      });
    }

    return changes;
  }

  /**
   * Add value to history array (avoiding duplicates)
   * @param {Object} entry - Device entry
   * @param {string} field - History field name
   * @param {string} value - Value to add
   */
  _addToHistory(entry, field, value) {
    if (!value) return;
    if (!entry[field]) entry[field] = [];
    
    const lowerValue = typeof value === 'string' ? value.toLowerCase() : value;
    if (!entry[field].includes(lowerValue)) {
      entry[field].push(lowerValue);
      // Keep history limited
      if (entry[field].length > 10) {
        entry[field] = entry[field].slice(-10);
      }
    }
  }

  /**
   * Index device by IP for quick lookup
   * @param {Object} entry - Device entry
   */
  _indexDevice(entry) {
    if (entry.ipv4) {
      this.ipIndex.set(entry.ipv4, entry.mac);
    }
    
    if (entry.ipv6) {
      for (const v6 of entry.ipv6) {
        const addr = typeof v6 === 'string' ? v6 : v6.address;
        if (addr) {
          this.ipIndex.set(addr, entry.mac);
        }
      }
    }
  }

  /**
   * Prune entries older than retention period
   */
  _pruneOldEntries() {
    const cutoff = Date.now() - (this.config.retentionDays * 24 * 60 * 60 * 1000);
    
    for (const [mac, entry] of this.devices) {
      if (entry.lastSeen < cutoff) {
        this.devices.delete(mac);
        
        // Remove from IP index
        if (entry.ipv4) {
          this.ipIndex.delete(entry.ipv4);
        }
        if (entry.ipv6) {
          for (const v6 of entry.ipv6) {
            const addr = typeof v6 === 'string' ? v6 : v6.address;
            if (addr) this.ipIndex.delete(addr);
          }
        }
      }
    }
  }

  /**
   * Get device by MAC address
   * @param {string} mac - MAC address
   * @returns {Object|null} Device entry or null
   */
  getByMac(mac) {
    return this.devices.get(mac?.toLowerCase()) || null;
  }

  /**
   * Get device by IP address
   * @param {string} ip - IP address (v4 or v6)
   * @returns {Object|null} Device entry or null
   */
  getByIP(ip) {
    const mac = this.ipIndex.get(ip);
    return mac ? this.devices.get(mac) : null;
  }

  /**
   * Get all active devices (seen in last scan)
   * @returns {Array<Object>} Active device entries
   */
  getActiveDevices() {
    return Array.from(this.devices.values()).filter(d => d.isActive);
  }

  /**
   * Get all inactive devices (not seen in last scan)
   * @returns {Array<Object>} Inactive device entries
   */
  getInactiveDevices() {
    return Array.from(this.devices.values()).filter(d => !d.isActive);
  }

  /**
   * Get devices that haven't been seen in a while
   * @param {number} hours - Number of hours since last seen
   * @returns {Array<Object>} Stale device entries
   */
  getStaleDevices(hours = 24) {
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);
    return Array.from(this.devices.values()).filter(d => d.lastSeen < cutoff);
  }

  /**
   * Get new devices from recent scans
   * @param {number} hours - Number of hours to consider "new"
   * @returns {Array<Object>} New device entries
   */
  getNewDevices(hours = 24) {
    const cutoff = Date.now() - (hours * 60 * 60 * 1000);
    return Array.from(this.devices.values()).filter(d => d.firstSeen > cutoff);
  }

  /**
   * Get history statistics
   * @returns {Object} Statistics
   */
  getStats() {
    const devices = Array.from(this.devices.values());
    
    return {
      totalDevices: devices.length,
      activeDevices: devices.filter(d => d.isActive).length,
      inactiveDevices: devices.filter(d => !d.isActive).length,
      oldestDevice: devices.reduce((oldest, d) => 
        d.firstSeen < (oldest?.firstSeen || Infinity) ? d : oldest, null),
      newestDevice: devices.reduce((newest, d) => 
        d.firstSeen > (newest?.firstSeen || 0) ? d : newest, null),
      mostFrequentDevice: devices.reduce((most, d) => 
        d.seenCount > (most?.seenCount || 0) ? d : most, null),
    };
  }

  /**
   * Get all devices
   * @returns {Array<Object>} All device entries
   */
  getAllDevices() {
    return Array.from(this.devices.values());
  }

  /**
   * Clear all history
   */
  clear() {
    this.devices.clear();
    this.ipIndex.clear();
    this.dirty = true;
  }

  /**
   * Export history to JSON
   * @returns {Object} Exportable history object
   */
  export() {
    return {
      version: 1,
      exportedAt: Date.now(),
      devices: Array.from(this.devices.values()),
    };
  }

  /**
   * Import history from JSON
   * @param {Object} data - History data to import
   * @param {boolean} merge - Whether to merge with existing (true) or replace (false)
   */
  import(data, merge = true) {
    if (!data?.devices || !Array.isArray(data.devices)) {
      throw new Error('Invalid history data format');
    }

    if (!merge) {
      this.devices.clear();
      this.ipIndex.clear();
    }

    for (const device of data.devices) {
      if (!device.mac) continue;
      
      const mac = device.mac.toLowerCase();
      
      if (merge && this.devices.has(mac)) {
        // Merge with existing entry
        const existing = this.devices.get(mac);
        existing.firstSeen = Math.min(existing.firstSeen, device.firstSeen || Date.now());
        existing.lastSeen = Math.max(existing.lastSeen, device.lastSeen || 0);
        existing.seenCount = (existing.seenCount || 0) + (device.seenCount || 0);
        
        // Merge histories
        if (device.ipHistory) {
          existing.ipHistory = [...new Set([...(existing.ipHistory || []), ...device.ipHistory])];
        }
        if (device.hostnameHistory) {
          existing.hostnameHistory = [...new Set([...(existing.hostnameHistory || []), ...device.hostnameHistory])];
        }
      } else {
        this.devices.set(mac, device);
      }
      
      this._indexDevice(device);
    }

    this.dirty = true;
  }
}

/**
 * Singleton instance
 */
let instance = null;

/**
 * Get or create singleton instance
 * @param {Object} config - Optional configuration
 * @returns {DeviceHistory} Singleton instance
 */
export function getDeviceHistory(config) {
  if (!instance) {
    instance = new DeviceHistory(config);
  }
  return instance;
}
