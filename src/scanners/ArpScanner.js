/**
 * ARP Scanner - Fast MAC/IP discovery using ARP tables and arp-scan
 */

import BaseScanner from './BaseScanner.js';
import { executeCommand, commandExists } from '../utils/CommandRunner.js';
import { normalizeMac } from '../utils/NetworkUtils.js';

/**
 * ARP Scanner for fast local network device discovery
 * Uses arp-scan or arp command to discover MAC/IP pairs
 */
export default class ArpScanner extends BaseScanner {
  constructor(options = {}) {
    super('ArpScanner', options);
    this.useArpScan = false;
  }

  /**
   * Start ARP scanning
   * @param {Object} config - Scan configuration
   * @param {string} config.interface - Network interface to scan
   * @param {string} config.cidr - CIDR range to scan
   */
  async start(config) {
    this._onStart();

    try {
      // Check which tool is available
      this.useArpScan = await commandExists('arp-scan');

      const devices = this.useArpScan
        ? await this._scanWithArpScan(config)
        : await this._scanWithArp(config);

      devices.forEach((device) => this._addDevice(device));

      this._onComplete();
    } catch (error) {
      this._onError(error);
      throw error;
    }
  }

  /**
   * Stop scanning (ARP scan is synchronous, so this is a no-op)
   */
  async stop() {
    if (this.running) {
      this.running = false;
    }
  }

  /**
   * Scan using arp-scan command
   * @param {Object} config - Scan configuration
   * @returns {Promise<Array>} Array of discovered devices
   */
  async _scanWithArpScan(config) {
    try {
      const command = config.interface
        ? `arp-scan -I ${config.interface} -l`
        : 'arp-scan -l';

      const output = await executeCommand(command);
      return this._parseArpScanOutput(output);
    } catch (error) {
      console.error('arp-scan failed:', error.message);
      return [];
    }
  }

  /**
   * Scan using arp command (fallback)
   * @returns {Promise<Array>} Array of discovered devices
   */
  async _scanWithArp() {
    try {
      const command = process.platform === 'win32' ? 'arp -a' : 'arp -a';
      const output = await executeCommand(command);
      return this._parseArpOutput(output);
    } catch (error) {
      console.error('arp failed:', error.message);
      return [];
    }
  }

  /**
   * Parse arp-scan output
   * Example line: 192.168.1.1	00:11:22:33:44:55	Vendor Name
   * @param {string} output - Command output
   * @returns {Array} Parsed devices
   */
  _parseArpScanOutput(output) {
    const devices = [];
    const lines = output.split('\n');

    for (const line of lines) {
      // Skip headers and empty lines
      if (!line || line.startsWith('Interface:') || line.startsWith('Starting')) {
        continue;
      }

      // Match IP, MAC, and optional vendor
      const match = line.match(
        /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-fA-F:]{17})\s*(.*)/
      );

      if (match) {
        const [, ip, mac, vendor] = match;
        devices.push({
          ip,
          mac: normalizeMac(mac),
          manufacturer: vendor.trim() || undefined,
          lastSeen: new Date().toISOString(),
          source: 'arp-scan',
        });
      }
    }

    return devices;
  }

  /**
   * Parse arp command output
   * Handles different formats for Linux, macOS, and Windows
   * @param {string} output - Command output
   * @returns {Array} Parsed devices
   */
  _parseArpOutput(output) {
    const devices = [];
    const lines = output.split('\n');

    for (const line of lines) {
      let ip, mac;

      if (process.platform === 'win32') {
        // Windows format: 192.168.1.1      00-11-22-33-44-55     dynamic
        const match = line.match(
          /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([\da-fA-F-]{17})/
        );
        if (match) {
          [, ip, mac] = match;
        }
      } else {
        // Unix format: hostname (192.168.1.1) at 00:11:22:33:44:55 [ether] on en0
        const match = line.match(
          /\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)\s+at\s+([\da-fA-F:]{17})/
        );
        if (match) {
          [, ip, mac] = match;
        }
      }

      if (ip && mac) {
        // Filter out incomplete or invalid entries
        if (mac.includes('ff:ff:ff') || mac.includes('incomplete')) {
          continue;
        }

        devices.push({
          ip,
          mac: normalizeMac(mac),
          lastSeen: new Date().toISOString(),
          source: 'arp',
        });
      }
    }

    return devices;
  }
}
