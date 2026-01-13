/**
 * Data Aggregator - Merges data from multiple sources into unified Device objects
 * Handles data enrichment with manufacturer, OS, and usage information
 * Uses MAC-based keying for proper dual-stack (IPv4/IPv6) device correlation
 */

import Device from '../models/Device.js';
import { manufacturerResolver } from './ManufacturerResolver.js';
import { osDetector } from './OsDetector.js';
import { usageInferrer } from './UsageInferrer.js';
import { normalizeMac } from '../utils/NetworkUtils.js';
import eventBus, { Events } from '../utils/EventBus.js';

/**
 * Aggregate and enrich device data from multiple sources
 */
export default class DataAggregator {
  constructor() {
    // Primary device map keyed by MAC address
    this.devices = new Map();
    
    // Secondary indexes for fast lookup
    this.ipv4Index = new Map(); // IPv4 -> MAC
    this.ipv6Index = new Map(); // IPv6 -> MAC

    // Subscribe to device events
    this._setupEventListeners();
  }

  /**
   * Set up event listeners for device discovery and updates
   */
  _setupEventListeners() {
    // Listen for device discoveries and updates
    eventBus.subscribe(Events.DEVICE_DISCOVERED, (data) => {
      this.addDevice(data.device);
    });

    eventBus.subscribe(Events.DEVICE_UPDATED, (data) => {
      this.updateDevice(data.device);
    });
  }

  /**
   * Generate a device key - prefers MAC for proper dual-stack correlation
   * @param {Object} deviceData - Device data
   * @returns {string|null} Device key
   */
  _getDeviceKey(deviceData) {
    // Prefer MAC address for dual-stack correlation
    if (deviceData.mac) {
      return `mac:${normalizeMac(deviceData.mac)}`;
    }
    
    // Fall back to IPv4
    if (deviceData.ipv4 || deviceData.ip) {
      return `ipv4:${deviceData.ipv4 || deviceData.ip}`;
    }
    
    // Fall back to IPv6
    if (deviceData.ipv6?.length > 0) {
      const addr = typeof deviceData.ipv6[0] === 'string' 
        ? deviceData.ipv6[0] 
        : deviceData.ipv6[0].address;
      return `ipv6:${addr}`;
    }
    
    return null;
  }

  /**
   * Find existing device by any identifier
   * @param {Object} deviceData - Device data
   * @returns {Device|null} Existing device or null
   */
  _findExistingDevice(deviceData) {
    // Check by MAC first (most reliable)
    if (deviceData.mac) {
      const key = `mac:${normalizeMac(deviceData.mac)}`;
      if (this.devices.has(key)) {
        return { device: this.devices.get(key), key };
      }
    }
    
    // Check by IPv4 index
    const ipv4 = deviceData.ipv4 || deviceData.ip;
    if (ipv4 && this.ipv4Index.has(ipv4)) {
      const key = this.ipv4Index.get(ipv4);
      if (this.devices.has(key)) {
        return { device: this.devices.get(key), key };
      }
    }
    
    // Check by IPv6 index
    if (deviceData.ipv6?.length > 0) {
      for (const v6 of deviceData.ipv6) {
        const addr = typeof v6 === 'string' ? v6 : v6.address;
        if (this.ipv6Index.has(addr)) {
          const key = this.ipv6Index.get(addr);
          if (this.devices.has(key)) {
            return { device: this.devices.get(key), key };
          }
        }
      }
    }
    
    return null;
  }

  /**
   * Update indexes for a device
   * @param {string} key - Device key
   * @param {Device} device - Device object
   */
  _updateIndexes(key, device) {
    // Index IPv4
    if (device.ipv4 || device.ip) {
      this.ipv4Index.set(device.ipv4 || device.ip, key);
    }
    
    // Index all IPv6 addresses
    for (const v6 of device.ipv6 || []) {
      const addr = typeof v6 === 'string' ? v6 : v6.address;
      this.ipv6Index.set(addr, key);
    }
  }

  /**
   * Add a new device or update existing device
   * @param {Object} deviceData - Raw device data
   * @returns {Device} Device object
   */
  addDevice(deviceData) {
    // Try to find existing device first
    const existing = this._findExistingDevice(deviceData);

    if (existing) {
      // Update existing device
      existing.device.merge(deviceData);
      this._updateIndexes(existing.key, existing.device);
      this.enrichDevice(existing.device);
      return existing.device;
    }

    // Get key for new device
    const key = this._getDeviceKey(deviceData);

    if (!key) {
      console.warn('Device without IP or MAC:', deviceData);
      return null;
    }

    // Check if key exists (shouldn't happen, but safety check)
    if (this.devices.has(key)) {
      const device = this.devices.get(key);
      device.merge(deviceData);
      this._updateIndexes(key, device);
      this.enrichDevice(device);
      return device;
    }

    // Create new device
    const device = new Device(deviceData);
    this.devices.set(key, device);
    this._updateIndexes(key, device);

    // Enrich device data
    this.enrichDevice(device);

    return device;
  }

  /**
   * Update an existing device
   * @param {Object} deviceData - Device data to merge
   * @returns {Device|null} Updated device or null
   */
  updateDevice(deviceData) {
    const existing = this._findExistingDevice(deviceData);

    if (existing) {
      existing.device.merge(deviceData);
      this._updateIndexes(existing.key, existing.device);
      this.enrichDevice(existing.device);
      return existing.device;
    }

    // Device doesn't exist, add it
    return this.addDevice(deviceData);
  }

  /**
   * Enrich device with manufacturer, OS, and usage information
   * @param {Device} device - Device to enrich
   */
  enrichDevice(device) {
    let enriched = false;

    // Resolve manufacturer if MAC is available
    if (device.mac && !device.manufacturer) {
      const manufacturer = manufacturerResolver.resolve(device.mac);
      if (manufacturer) {
        device.manufacturer = manufacturer;
        enriched = true;
      }
    }

    // Detect OS if not already set
    if (!device.os) {
      const osInfo = osDetector.detect(device.toObject());
      if (osInfo.os) {
        device.os = osInfo.os;
        device.osVersion = osInfo.osVersion;
        enriched = true;
      }
    }

    // Infer device usage if not set
    if (!device.usage) {
      const usageInfo = usageInferrer.infer(device.toObject());
      if (usageInfo.usage && usageInfo.confidence > 30) {
        device.usage = usageInfo.usage;
        enriched = true;
      }
    }

    // Update device confidence
    device.updateConfidence();

    // Emit enrichment event if device was enriched
    if (enriched) {
      eventBus.emit(Events.DEVICE_ENRICHED, {
        device: device.toObject(),
      });
    }
  }

  /**
   * Get all devices
   * @returns {Array<Device>} Array of devices
   */
  getDevices() {
    return Array.from(this.devices.values());
  }

  /**
   * Get device by key (MAC, IPv4, or IPv6 based key)
   * @param {string} key - Device key
   * @returns {Device|null} Device or null
   */
  getDevice(key) {
    return this.devices.get(key) || null;
  }

  /**
   * Get device by IP address (IPv4 or IPv6)
   * @param {string} ip - IP address
   * @returns {Device|null} Device or null
   */
  getDeviceByIP(ip) {
    // Check IPv4 index
    if (this.ipv4Index.has(ip)) {
      const key = this.ipv4Index.get(ip);
      return this.devices.get(key) || null;
    }
    
    // Check IPv6 index
    if (this.ipv6Index.has(ip)) {
      const key = this.ipv6Index.get(ip);
      return this.devices.get(key) || null;
    }
    
    // Fall back to linear search
    for (const device of this.devices.values()) {
      if (device.ip === ip || device.ipv4 === ip) {
        return device;
      }
      for (const v6 of device.ipv6 || []) {
        const addr = typeof v6 === 'string' ? v6 : v6.address;
        if (addr === ip) return device;
      }
    }
    return null;
  }

  /**
   * Get device by MAC address
   * @param {string} mac - MAC address
   * @returns {Device|null} Device or null
   */
  getDeviceByMAC(mac) {
    const normalized = normalizeMac(mac);
    const key = `mac:${normalized}`;
    return this.devices.get(key) || null;
  }

  /**
   * Get devices by usage type
   * @param {string} usage - Usage type
   * @returns {Array<Device>} Array of devices
   */
  getDevicesByUsage(usage) {
    return this.getDevices().filter((device) => device.usage === usage);
  }

  /**
   * Get devices by manufacturer
   * @param {string} manufacturer - Manufacturer name
   * @returns {Array<Device>} Array of devices
   */
  getDevicesByManufacturer(manufacturer) {
    return this.getDevices().filter((device) =>
      device.manufacturer?.toLowerCase().includes(manufacturer.toLowerCase())
    );
  }

  /**
   * Get devices by OS
   * @param {string} os - Operating system
   * @returns {Array<Device>} Array of devices
   */
  getDevicesByOS(os) {
    return this.getDevices().filter((device) =>
      device.os?.toLowerCase().includes(os.toLowerCase())
    );
  }

  /**
   * Remove a device
   * @param {string} key - Device key or MAC address
   * @returns {boolean} True if device was removed
   */
  removeDevice(key) {
    // Try direct key first
    if (this.devices.has(key)) {
      const device = this.devices.get(key);
      this._removeFromIndexes(device);
      return this.devices.delete(key);
    }
    
    // Try as MAC address
    const macKey = `mac:${normalizeMac(key)}`;
    if (this.devices.has(macKey)) {
      const device = this.devices.get(macKey);
      this._removeFromIndexes(device);
      return this.devices.delete(macKey);
    }
    
    return false;
  }

  /**
   * Remove device from indexes
   * @param {Device} device - Device to remove from indexes
   */
  _removeFromIndexes(device) {
    if (device.ipv4 || device.ip) {
      this.ipv4Index.delete(device.ipv4 || device.ip);
    }
    for (const v6 of device.ipv6 || []) {
      const addr = typeof v6 === 'string' ? v6 : v6.address;
      this.ipv6Index.delete(addr);
    }
  }

  /**
   * Clear all devices
   */
  clear() {
    this.devices.clear();
    this.ipv4Index.clear();
    this.ipv6Index.clear();
  }

  /**
   * Get statistics about aggregated devices
   * @returns {Object} Statistics
   */
  getStats() {
    const devices = this.getDevices();

    // Count by usage type
    const usageTypes = {};
    devices.forEach((device) => {
      const usage = device.usage || 'Unknown';
      usageTypes[usage] = (usageTypes[usage] || 0) + 1;
    });

    // Count by OS
    const osTypes = {};
    devices.forEach((device) => {
      const os = device.os || 'Unknown';
      osTypes[os] = (osTypes[os] || 0) + 1;
    });

    // Count by manufacturer
    const manufacturers = {};
    devices.forEach((device) => {
      const mfr = device.manufacturer || 'Unknown';
      manufacturers[mfr] = (manufacturers[mfr] || 0) + 1;
    });

    // Calculate average confidence
    const avgConfidence =
      devices.reduce((sum, device) => sum + device.confidence, 0) / devices.length || 0;

    return {
      totalDevices: devices.length,
      usageTypes,
      osTypes,
      manufacturers: Object.entries(manufacturers)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .reduce((obj, [key, val]) => ({ ...obj, [key]: val }), {}),
      averageConfidence: Math.round(avgConfidence),
      withHostname: devices.filter((d) => d.hostname).length,
      withManufacturer: devices.filter((d) => d.manufacturer).length,
      withOS: devices.filter((d) => d.os).length,
      withUsage: devices.filter((d) => d.usage).length,
    };
  }

  /**
   * Export devices to array of plain objects
   * @returns {Array<Object>} Array of device objects
   */
  export() {
    return this.getDevices().map((device) => device.toObject());
  }

  /**
   * Import devices from array of plain objects
   * @param {Array<Object>} devicesData - Array of device data
   */
  import(devicesData) {
    for (const deviceData of devicesData) {
      this.addDevice(deviceData);
    }
  }
}

// Export singleton instance
export const dataAggregator = new DataAggregator();
