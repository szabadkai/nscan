/**
 * Device model - Represents a discovered network device
 */

import { isValidIP, normalizeMac, isValidIPv6, getIPv6Type } from '../utils/NetworkUtils.js';

/**
 * Device class representing a network device with all its properties
 * Supports dual-stack (IPv4 + IPv6) addressing
 */
export default class Device {
  /**
   * Create a device
   * @param {Object} data - Device data
   */
  constructor(data = {}) {
    // Primary IP (for backward compatibility - prefers IPv4)
    this.ip = data.ip || null;
    
    // Dual-stack support
    this.ipv4 = data.ipv4 || data.ip || null;
    this.ipv6 = this._normalizeIPv6Array(data.ipv6);
    
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
    
    // Additional metadata
    this.workgroup = data.workgroup || null;
    this.fqdn = data.fqdn || null;
    
    // Discovery metadata
    this.discoveredVia = data.discoveredVia || [];
  }

  /**
   * Normalize IPv6 array with type information
   * @param {Array|string} ipv6 - IPv6 address(es)
   * @returns {Array} Normalized IPv6 array
   */
  _normalizeIPv6Array(ipv6) {
    if (!ipv6) return [];
    
    const addresses = Array.isArray(ipv6) ? ipv6 : [ipv6];
    return addresses.map(addr => {
      if (typeof addr === 'string') {
        return {
          address: addr,
          type: getIPv6Type(addr),
        };
      }
      return addr;
    }).filter(Boolean);
  }

  /**
   * Validate device data
   * @returns {Object} Validation result
   */
  validate() {
    const errors = [];
    const warnings = [];

    // Must have at least IP, IPv6, or MAC
    if (!this.ip && !this.ipv4 && this.ipv6.length === 0 && !this.mac) {
      errors.push('Device must have at least an IP address (v4 or v6) or MAC address');
    }

    // Validate IPv4 format
    if (this.ipv4 && !isValidIP(this.ipv4)) {
      errors.push(`Invalid IPv4 address format: ${this.ipv4}`);
    }

    // Validate IPv6 addresses
    for (const v6 of this.ipv6) {
      const addr = typeof v6 === 'string' ? v6 : v6.address;
      if (!isValidIPv6(addr)) {
        errors.push(`Invalid IPv6 address format: ${addr}`);
      }
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
    if (this.ip || this.ipv4) score += 15;
    if (this.ipv6.length > 0) score += 10;
    if (this.mac) score += 20;

    // Device information
    if (this.hostname) score += 10;
    if (this.manufacturer) score += 10;
    if (this.os) score += 15;
    if (this.model) score += 10;
    if (this.usage) score += 10;

    // Additional data
    if (this.ports.length > 0) score += 5;
    
    // Bonus for dual-stack
    if ((this.ip || this.ipv4) && this.ipv6.length > 0) score += 5;

    return Math.min(score, 100);
  }

  /**
   * Update confidence score
   */
  updateConfidence() {
    this.confidence = this._calculateConfidence();
  }

  /**
   * Add an IPv6 address to the device
   * @param {string|Object} address - IPv6 address or address object
   */
  addIPv6(address) {
    const normalized = typeof address === 'string' 
      ? { address, type: getIPv6Type(address) }
      : address;
    
    // Check if already exists
    const exists = this.ipv6.some(v6 => 
      (typeof v6 === 'string' ? v6 : v6.address) === normalized.address
    );
    
    if (!exists) {
      this.ipv6.push(normalized);
    }
  }

  /**
   * Get the primary IPv6 address (prefers global over link-local)
   * @returns {string|null} Primary IPv6 address
   */
  getPrimaryIPv6() {
    if (this.ipv6.length === 0) return null;
    
    // Prefer global unicast
    const global = this.ipv6.find(v6 => v6.type === 'global');
    if (global) return global.address;
    
    // Then unique-local
    const uniqueLocal = this.ipv6.find(v6 => v6.type === 'unique-local');
    if (uniqueLocal) return uniqueLocal.address;
    
    // Fall back to link-local
    return this.ipv6[0].address;
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
    this.ipv4 = data.ipv4 || data.ip || this.ipv4;
    this.mac = data.mac ? normalizeMac(data.mac) : this.mac;
    this.hostname = data.hostname || this.hostname;
    this.manufacturer = data.manufacturer || this.manufacturer;
    this.os = data.os || this.os;
    this.osVersion = data.osVersion || this.osVersion;
    this.model = data.model || this.model;
    this.usage = data.usage || this.usage;
    this.workgroup = data.workgroup || this.workgroup;
    this.fqdn = data.fqdn || this.fqdn;

    // Merge IPv6 addresses
    if (data.ipv6) {
      const newAddrs = Array.isArray(data.ipv6) ? data.ipv6 : [data.ipv6];
      for (const addr of newAddrs) {
        this.addIPv6(addr);
      }
    }

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

    if (data.discoveredVia) {
      this.discoveredVia = [...new Set([...this.discoveredVia, ...data.discoveredVia])];
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
      ipv4: this.ipv4,
      ipv6: this.ipv6,
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
      workgroup: this.workgroup,
      fqdn: this.fqdn,
      discoveredVia: this.discoveredVia,
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
    if (this.ipv4 || this.ip) parts.push(`(${this.ipv4 || this.ip})`);
    if (this.ipv6.length > 0) {
      const primaryV6 = this.getPrimaryIPv6();
      if (primaryV6) parts.push(`[${primaryV6}]`);
    }
    if (this.mac) parts.push(`[${this.mac}]`);
    if (this.manufacturer) parts.push(`- ${this.manufacturer}`);
    if (this.usage) parts.push(`- ${this.usage}`);

    return parts.join(' ') || 'Unknown Device';
  }
}
