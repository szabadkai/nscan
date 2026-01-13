/**
 * NDP Scanner - IPv6 Neighbor Discovery Protocol scanner
 * Discovers IPv6 devices using NDP (equivalent of ARP for IPv6)
 */

import BaseScanner from './BaseScanner.js';
import { executeCommand, commandExists } from '../utils/CommandRunner.js';
import { normalizeMac, isValidIPv6, getIPv6Type } from '../utils/NetworkUtils.js';

/**
 * NDP Scanner for IPv6 neighbor discovery
 * Uses platform-specific commands to discover IPv6 neighbors
 */
export default class NdpScanner extends BaseScanner {
  constructor(options = {}) {
    super('NdpScanner', options);
    this.platform = process.platform;
  }

  /**
   * Start NDP scanning
   * @param {Object} config - Scan configuration
   * @param {string} config.interface - Network interface to scan
   */
  async start(config) {
    this._onStart();

    try {
      const devices = await this._scanNeighbors(config);
      devices.forEach((device) => this._addDevice(device));
      this._onComplete();
    } catch (error) {
      this._onError(error);
      throw error;
    }
  }

  /**
   * Stop scanning (NDP scan is synchronous, so this is a no-op)
   */
  async stop() {
    if (this.running) {
      this.running = false;
    }
  }

  /**
   * Scan for IPv6 neighbors using platform-specific commands
   * @param {Object} config - Scan configuration
   * @returns {Promise<Array>} Array of discovered devices
   */
  async _scanNeighbors(config) {
    const devices = [];

    try {
      if (this.platform === 'darwin') {
        // macOS: use ndp -an
        const ndpDevices = await this._scanWithNdp(config);
        devices.push(...ndpDevices);
      } else if (this.platform === 'linux') {
        // Linux: use ip -6 neigh
        const ipDevices = await this._scanWithIpNeigh(config);
        devices.push(...ipDevices);
      } else if (this.platform === 'win32') {
        // Windows: use netsh interface ipv6 show neighbors
        const netshDevices = await this._scanWithNetsh(config);
        devices.push(...netshDevices);
      }

      // Also try to ping multicast all-nodes address to populate neighbor cache
      await this._pingMulticast(config.interface);

      // Re-scan after ping to get newly populated entries
      if (this.platform === 'darwin') {
        const newDevices = await this._scanWithNdp(config);
        this._mergeDevices(devices, newDevices);
      } else if (this.platform === 'linux') {
        const newDevices = await this._scanWithIpNeigh(config);
        this._mergeDevices(devices, newDevices);
      }
    } catch (error) {
      console.warn('NDP scan warning:', error.message);
    }

    return devices;
  }

  /**
   * Merge new devices into existing array, avoiding duplicates
   * @param {Array} existing - Existing devices
   * @param {Array} newDevices - New devices to merge
   */
  _mergeDevices(existing, newDevices) {
    for (const device of newDevices) {
      const exists = existing.some(d => 
        d.mac === device.mac && 
        d.ipv6?.[0]?.address === device.ipv6?.[0]?.address
      );
      if (!exists) {
        existing.push(device);
      }
    }
  }

  /**
   * Ping IPv6 multicast all-nodes address to populate neighbor cache
   * @param {string} iface - Network interface
   */
  async _pingMulticast(iface) {
    try {
      const pingCmd = this.platform === 'darwin' 
        ? `ping6 -c 2 -I ${iface || 'en0'} ff02::1`
        : this.platform === 'linux'
        ? `ping -6 -c 2 -I ${iface || 'eth0'} ff02::1`
        : null;

      if (pingCmd) {
        await executeCommand(pingCmd, { timeout: 5000 }).catch(() => {});
      }
    } catch {
      // Ignore ping failures
    }
  }

  /**
   * Scan using ndp command (macOS)
   * @param {Object} config - Scan configuration
   * @returns {Promise<Array>} Array of discovered devices
   */
  async _scanWithNdp(config) {
    try {
      // ndp -an shows all neighbors
      const output = await executeCommand('ndp -an');
      return this._parseNdpOutput(output, config.interface);
    } catch (error) {
      console.warn('ndp command failed:', error.message);
      return [];
    }
  }

  /**
   * Parse ndp command output (macOS)
   * Example line: fe80::1%en0 00:11:22:33:44:55 en0 23s S R
   * @param {string} output - Command output
   * @param {string} filterInterface - Interface to filter by (optional)
   * @returns {Array} Parsed devices
   */
  _parseNdpOutput(output, filterInterface) {
    const devices = [];
    const lines = output.split('\n');

    for (const line of lines) {
      // Skip header and empty lines
      if (!line.trim() || line.includes('Neighbor') || line.includes('Address')) {
        continue;
      }

      // Match IPv6, MAC, and interface
      // Format: fe80::1%en0  at 00:11:22:33:44:55 on en0 [ethernet]
      // Or: fe80::1%en0  00:11:22:33:44:55  en0  permanent  R
      const match = line.match(
        /([a-fA-F0-9:]+(?:%\w+)?)\s+(?:at\s+)?([\da-fA-F:]{17})\s+(?:on\s+)?(\w+)/
      );

      if (match) {
        const [, ipv6, mac, iface] = match;

        // Skip if filtering by interface and doesn't match
        if (filterInterface && iface !== filterInterface) {
          continue;
        }

        // Skip incomplete or invalid entries
        if (mac.includes('incomplete') || mac === '(incomplete)') {
          continue;
        }

        const normalizedMac = normalizeMac(mac);
        const cleanIPv6 = ipv6.split('%')[0]; // Remove zone ID for storage

        if (isValidIPv6(cleanIPv6)) {
          devices.push({
            mac: normalizedMac,
            ipv6: [{
              address: cleanIPv6,
              type: getIPv6Type(cleanIPv6),
              interface: iface,
            }],
            lastSeen: new Date().toISOString(),
            source: 'ndp',
            discoveredVia: ['ndp'],
          });
        }
      }
    }

    return devices;
  }

  /**
   * Scan using ip -6 neigh command (Linux)
   * @param {Object} config - Scan configuration
   * @returns {Promise<Array>} Array of discovered devices
   */
  async _scanWithIpNeigh(config) {
    try {
      const command = config.interface 
        ? `ip -6 neigh show dev ${config.interface}`
        : 'ip -6 neigh show';
      const output = await executeCommand(command);
      return this._parseIpNeighOutput(output, config.interface);
    } catch (error) {
      console.warn('ip -6 neigh failed:', error.message);
      return [];
    }
  }

  /**
   * Parse ip -6 neigh output (Linux)
   * Example line: fe80::1 dev eth0 lladdr 00:11:22:33:44:55 STALE
   * @param {string} output - Command output
   * @param {string} filterInterface - Interface to filter by (optional)
   * @returns {Array} Parsed devices
   */
  _parseIpNeighOutput(output, filterInterface) {
    const devices = [];
    const lines = output.split('\n');

    for (const line of lines) {
      if (!line.trim()) continue;

      // Match IPv6, interface, and MAC
      const match = line.match(
        /([a-fA-F0-9:]+)\s+dev\s+(\w+)\s+lladdr\s+([\da-fA-F:]{17})\s+(\w+)/
      );

      if (match) {
        const [, ipv6, iface, mac, state] = match;

        // Skip if filtering by interface and doesn't match
        if (filterInterface && iface !== filterInterface) {
          continue;
        }

        // Skip FAILED entries
        if (state === 'FAILED') {
          continue;
        }

        const normalizedMac = normalizeMac(mac);

        if (isValidIPv6(ipv6)) {
          devices.push({
            mac: normalizedMac,
            ipv6: [{
              address: ipv6,
              type: getIPv6Type(ipv6),
              interface: iface,
            }],
            lastSeen: new Date().toISOString(),
            source: 'ip-neigh',
            discoveredVia: ['ndp'],
          });
        }
      }
    }

    return devices;
  }

  /**
   * Scan using netsh command (Windows)
   * @param {Object} config - Scan configuration
   * @returns {Promise<Array>} Array of discovered devices
   */
  async _scanWithNetsh(config) {
    try {
      const command = config.interface
        ? `netsh interface ipv6 show neighbors interface="${config.interface}"`
        : 'netsh interface ipv6 show neighbors';
      const output = await executeCommand(command);
      return this._parseNetshOutput(output, config.interface);
    } catch (error) {
      console.warn('netsh ipv6 neighbors failed:', error.message);
      return [];
    }
  }

  /**
   * Parse netsh ipv6 neighbors output (Windows)
   * @param {string} output - Command output
   * @param {string} filterInterface - Interface to filter by (optional)
   * @returns {Array} Parsed devices
   */
  _parseNetshOutput(output, filterInterface) {
    const devices = [];
    const lines = output.split('\n');
    let currentInterface = null;

    for (const line of lines) {
      // Check for interface header
      const ifaceMatch = line.match(/Interface\s+\d+:\s+(.+)/i);
      if (ifaceMatch) {
        currentInterface = ifaceMatch[1].trim();
        continue;
      }

      // Skip if filtering and interface doesn't match
      if (filterInterface && currentInterface !== filterInterface) {
        continue;
      }

      // Match IPv6 and MAC (format varies)
      // fe80::1   00-11-22-33-44-55   Reachable
      const match = line.match(
        /([a-fA-F0-9:]+)\s+([\da-fA-F-]{17})\s+(\w+)/
      );

      if (match) {
        const [, ipv6, mac, state] = match;

        // Skip unreachable entries
        if (state.toLowerCase() === 'unreachable') {
          continue;
        }

        // Windows uses dashes in MAC, normalize to colons
        const normalizedMac = normalizeMac(mac.replace(/-/g, ':'));

        if (isValidIPv6(ipv6)) {
          devices.push({
            mac: normalizedMac,
            ipv6: [{
              address: ipv6,
              type: getIPv6Type(ipv6),
              interface: currentInterface,
            }],
            lastSeen: new Date().toISOString(),
            source: 'netsh',
            discoveredVia: ['ndp'],
          });
        }
      }
    }

    return devices;
  }
}
