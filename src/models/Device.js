/**
 * Device model - Represents a discovered network device
 */

import { isValidIP, normalizeMac } from '../utils/NetworkUtils.js';

/**
 * Device class representing a network device with all its properties
 */
export default class Device {
  /**
   * Create a device
   * @param {Object} data - Device data
   */
  constructor(data = {}) {
    this.ip = data.ip || null;
    this.mac = data.mac ? normalizeMac(data.mac) : null;
    this.hostname = data.hostname || null;
    this.manufacturer = data.manufacturer || null;
    this.os = data.os || null;
    this.osVersion = data.osVersion || null;
    this.model = data.model || null;
    this.usage = data.usage || null;
    this.ports = data.ports || [];
    this.services = data.services || [];
    this.sources = data.sources || [];
    this.lastSeen = data.lastSeen || new Date().toISOString();
    this.firstSeen = data.firstSeen || new Date().toISOString();
    this.confidence = data.confidence || this._calculateConfidence();
  }

  /**
   * Validate device data
   * @returns {Object} Validation result
   */
  validate() {
    const errors = [];
    const warnings = [];

    // Must have at least IP or MAC
    if (!this.ip && !this.mac) {
      errors.push('Device must have at least an IP address or MAC address');
    }

    // Validate IP format
    if (this.ip && !isValidIP(this.ip)) {
      errors.push(`Invalid IP address format: ${this.ip}`);
    }

    // Validate MAC format
    if (this.mac && !/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/i.test(this.mac)) {
      warnings.push(`Unusual MAC address format: ${this.mac}`);
    }

    // Validate ports are numbers
    if (this.ports.some((p) => typeof p !== 'number' || p < 0 || p > 65535)) {
      errors.push('Invalid port number in ports array');
    }

    return {
      valid: errors.length === 0,
      errors,
      warnings,
    };
  }

  /**
   * Calculate confidence score based on available data
   * @returns {number} Confidence score (0-100)
   */
  _calculateConfidence() {
    let score = 0;

    // Core identifiers
    if (this.ip) score += 20;
    if (this.mac) score += 20;

    // Device information
    if (this.hostname) score += 10;
    if (this.manufacturer) score += 10;
    if (this.os) score += 15;
    if (this.model) score += 10;
    if (this.usage) score += 10;

    // Additional data
    if (this.ports.length > 0) score += 5;

    return Math.min(score, 100);
  }

  /**
   * Update confidence score
   */
  updateConfidence() {
    this.confidence = this._calculateConfidence();
  }

  /**
   * Merge data from another device or data object
   * @param {Device|Object} other - Other device or data to merge
   * @returns {Device} This device (for chaining)
   */
  merge(other) {
    const data = other instanceof Device ? other.toObject() : other;

    // Update fields, preferring non-null values
    this.ip = data.ip || this.ip;
    this.mac = data.mac ? normalizeMac(data.mac) : this.mac;
    this.hostname = data.hostname || this.hostname;
    this.manufacturer = data.manufacturer || this.manufacturer;
    this.os = data.os || this.os;
    this.osVersion = data.osVersion || this.osVersion;
    this.model = data.model || this.model;
    this.usage = data.usage || this.usage;

    // Merge arrays (remove duplicates)
    if (data.ports) {
      this.ports = [...new Set([...this.ports, ...data.ports])];
    }

    if (data.services) {
      this.services = [...this.services, ...data.services];
    }

    if (data.sources) {
      this.sources = [...new Set([...this.sources, ...data.sources])];
    }

    // Update timestamps
    this.lastSeen = data.lastSeen || new Date().toISOString();

    // Recalculate confidence
    this.updateConfidence();

    return this;
  }

  /**
   * Get a unique identifier for this device
   * @returns {string} Unique identifier (IP or MAC)
   */
  getId() {
    return this.ip || this.mac || 'unknown';
  }

  /**
   * Get a display name for this device
   * @returns {string} Display name
   */
  getDisplayName() {
    return (
      this.hostname ||
      this.ip ||
      this.mac ||
      'Unknown Device'
    );
  }

  /**
   * Check if device has specific port open
   * @param {number} port - Port number
   * @returns {boolean} True if port is open
   */
  hasPort(port) {
    return this.ports.includes(port);
  }

  /**
   * Get service running on specific port
   * @param {number} port - Port number
   * @returns {Object|null} Service info or null
   */
  getService(port) {
    return this.services.find((s) => s.port === port) || null;
  }

  /**
   * Check if device is likely a specific type based on characteristics
   * @param {string} type - Device type to check
   * @returns {boolean} True if device matches type
   */
  isType(type) {
    if (!this.usage) return false;
    return this.usage.toLowerCase().includes(type.toLowerCase());
  }

  /**
   * Convert device to plain object
   * @returns {Object} Plain object representation
   */
  toObject() {
    return {
      ip: this.ip,
      mac: this.mac,
      hostname: this.hostname,
      manufacturer: this.manufacturer,
      os: this.os,
      osVersion: this.osVersion,
      model: this.model,
      usage: this.usage,
      ports: this.ports,
      services: this.services,
      sources: this.sources,
      lastSeen: this.lastSeen,
      firstSeen: this.firstSeen,
      confidence: this.confidence,
    };
  }

  /**
   * Convert device to JSON string
   * @param {boolean} pretty - Pretty print JSON
   * @returns {string} JSON string
   */
  toJSON(pretty = false) {
    return pretty
      ? JSON.stringify(this.toObject(), null, 2)
      : JSON.stringify(this.toObject());
  }

  /**
   * Create Device from plain object
   * @param {Object} data - Device data
   * @returns {Device} New Device instance
   */
  static fromObject(data) {
    return new Device(data);
  }

  /**
   * Create Device from JSON string
   * @param {string} json - JSON string
   * @returns {Device} New Device instance
   */
  static fromJSON(json) {
    return new Device(JSON.parse(json));
  }

  /**
   * Get a summary string for this device
   * @returns {string} Summary string
   */
  toString() {
    const parts = [];

    if (this.hostname) parts.push(this.hostname);
    if (this.ip) parts.push(`(${this.ip})`);
    if (this.mac) parts.push(`[${this.mac}]`);
    if (this.manufacturer) parts.push(`- ${this.manufacturer}`);
    if (this.usage) parts.push(`- ${this.usage}`);

    return parts.join(' ') || 'Unknown Device';
  }
}
