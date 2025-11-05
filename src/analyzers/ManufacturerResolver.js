/**
 * Manufacturer Resolver - Resolves MAC addresses to manufacturer names
 * Uses oui-data package for OUI (Organizationally Unique Identifier) lookup
 */

import ouiData from 'oui-data' with { type: 'json' };
import { getMacOUI, normalizeMac } from '../utils/NetworkUtils.js';

/**
 * Resolve MAC addresses to manufacturer names using OUI database
 */
export default class ManufacturerResolver {
  constructor() {
    // Cache for resolved manufacturers
    this.cache = new Map();

    // Load OUI database
    this.ouiDatabase = ouiData;
  }

  /**
   * Resolve a MAC address to manufacturer name
   * @param {string} mac - MAC address
   * @returns {string|null} Manufacturer name or null if not found
   */
  resolve(mac) {
    if (!mac) return null;

    // Normalize MAC address
    const normalizedMac = normalizeMac(mac);

    // Check cache first
    if (this.cache.has(normalizedMac)) {
      return this.cache.get(normalizedMac);
    }

    // Get OUI (first 3 octets)
    const oui = getMacOUI(normalizedMac);

    // Look up in database
    const manufacturer = this._lookupOUI(oui);

    // Cache the result
    this.cache.set(normalizedMac, manufacturer);

    return manufacturer;
  }

  /**
   * Lookup OUI in database
   * @param {string} oui - OUI string (XX:XX:XX)
   * @returns {string|null} Manufacturer name or null
   */
  _lookupOUI(oui) {
    if (!oui) return null;

    try {
      // Remove colons and convert to uppercase for lookup
      const ouiKey = oui.replace(/:/g, '').toUpperCase();

      // oui-data uses keys without colons in uppercase
      // Try direct lookup
      if (this.ouiDatabase[ouiKey]) {
        return this.ouiDatabase[ouiKey];
      }

      // Try with dashes (alternative format)
      const ouiWithDashes = oui.replace(/:/g, '-').toUpperCase();
      if (this.ouiDatabase[ouiWithDashes]) {
        return this.ouiDatabase[ouiWithDashes];
      }

      // Try lowercase variants
      const ouiLower = ouiKey.toLowerCase();
      if (this.ouiDatabase[ouiLower]) {
        return this.ouiDatabase[ouiLower];
      }

      return null;
    } catch (error) {
      console.error('OUI lookup error:', error.message);
      return null;
    }
  }

  /**
   * Bulk resolve multiple MAC addresses
   * @param {Array<string>} macs - Array of MAC addresses
   * @returns {Map<string, string>} Map of MAC to manufacturer
   */
  resolveBulk(macs) {
    const results = new Map();

    for (const mac of macs) {
      const manufacturer = this.resolve(mac);
      if (manufacturer) {
        results.set(mac, manufacturer);
      }
    }

    return results;
  }

  /**
   * Check if a MAC address is from a known manufacturer
   * @param {string} mac - MAC address
   * @returns {boolean} True if manufacturer is known
   */
  isKnown(mac) {
    return this.resolve(mac) !== null;
  }

  /**
   * Get confidence level for a MAC address resolution
   * @param {string} mac - MAC address
   * @returns {number} Confidence score (0-100)
   */
  getConfidence(mac) {
    const manufacturer = this.resolve(mac);

    if (!manufacturer) {
      return 0;
    }

    // High confidence if found in OUI database
    return 90;
  }

  /**
   * Check if MAC is a locally administered address
   * @param {string} mac - MAC address
   * @returns {boolean} True if locally administered
   */
  isLocallyAdministered(mac) {
    if (!mac) return false;

    const normalizedMac = normalizeMac(mac);
    const firstOctet = parseInt(normalizedMac.substring(0, 2), 16);

    // Check if second-least significant bit of first octet is set
    return (firstOctet & 0x02) !== 0;
  }

  /**
   * Check if MAC is a multicast address
   * @param {string} mac - MAC address
   * @returns {boolean} True if multicast
   */
  isMulticast(mac) {
    if (!mac) return false;

    const normalizedMac = normalizeMac(mac);
    const firstOctet = parseInt(normalizedMac.substring(0, 2), 16);

    // Check if least significant bit of first octet is set
    return (firstOctet & 0x01) !== 0;
  }

  /**
   * Clear the cache
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache statistics
   */
  getCacheStats() {
    return {
      size: this.cache.size,
      entries: Array.from(this.cache.entries()),
    };
  }
}

// Export singleton instance
export const manufacturerResolver = new ManufacturerResolver();
