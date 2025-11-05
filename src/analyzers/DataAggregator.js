/**
 * Data Aggregator - Merges data from multiple sources into unified Device objects
 * Handles data enrichment with manufacturer, OS, and usage information
 */

import Device from '../models/Device.js';
import { manufacturerResolver } from './ManufacturerResolver.js';
import { osDetector } from './OsDetector.js';
import { usageInferrer } from './UsageInferrer.js';
import eventBus, { Events } from '../utils/EventBus.js';

/**
 * Aggregate and enrich device data from multiple sources
 */
export default class DataAggregator {
  constructor() {
    // Map of devices by ID (IP or MAC)
    this.devices = new Map();

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
   * Add a new device or update existing device
   * @param {Object} deviceData - Raw device data
   * @returns {Device} Device object
   */
  addDevice(deviceData) {
    // Get device ID (prefer IP over MAC)
    const id = deviceData.ip || deviceData.mac;

    if (!id) {
      console.warn('Device without IP or MAC:', deviceData);
      return null;
    }

    let device;

    if (this.devices.has(id)) {
      // Update existing device
      device = this.devices.get(id);
      device.merge(deviceData);
    } else {
      // Create new device
      device = new Device(deviceData);
      this.devices.set(id, device);
    }

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
    const id = deviceData.ip || deviceData.mac;

    if (!id) {
      return null;
    }

    if (this.devices.has(id)) {
      const device = this.devices.get(id);
      device.merge(deviceData);
      this.enrichDevice(device);
      return device;
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
   * Get device by ID (IP or MAC)
   * @param {string} id - Device ID
   * @returns {Device|null} Device or null
   */
  getDevice(id) {
    return this.devices.get(id) || null;
  }

  /**
   * Get device by IP address
   * @param {string} ip - IP address
   * @returns {Device|null} Device or null
   */
  getDeviceByIP(ip) {
    for (const device of this.devices.values()) {
      if (device.ip === ip) {
        return device;
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
    for (const device of this.devices.values()) {
      if (device.mac === mac) {
        return device;
      }
    }
    return null;
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
   * @param {string} id - Device ID
   * @returns {boolean} True if device was removed
   */
  removeDevice(id) {
    return this.devices.delete(id);
  }

  /**
   * Clear all devices
   */
  clear() {
    this.devices.clear();
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
