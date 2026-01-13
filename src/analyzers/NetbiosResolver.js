/**
 * NetBIOS Resolver - Fast Windows hostname discovery using multiple methods
 */

import { executeCommand } from '../utils/CommandRunner.js';
import { platform } from 'os';
import dns from 'dns';
import { promisify } from 'util';

const reverseLookup = promisify(dns.reverse);

/**
 * Resolves Windows hostnames quickly using multiple methods:
 * 1. smbutil (macOS native - most reliable)
 * 2. nmblookup (Samba)
 * 3. Reverse DNS lookup (fallback)
 */
export default class NetbiosResolver {
  constructor() {
    this.tools = [];
    this.available = false;
  }

  /**
   * Check which hostname resolution tools are available
   * @returns {Promise<boolean>} True if any tool is available
   */
  async checkAvailability() {
    this.tools = [];

    // On macOS, try smbutil first (most reliable, always present)
    if (platform() === 'darwin') {
      try {
        await executeCommand('which smbutil', { timeout: 2000 });
        this.tools.push('smbutil');
      } catch {
        // smbutil not found
      }
    }

    // Try nmblookup (Samba)
    try {
      await executeCommand('which nmblookup', { timeout: 2000 });
      this.tools.push('nmblookup');
    } catch {
      // nmblookup not found
    }

    // Reverse DNS is always available as fallback
    this.tools.push('dns-reverse');

    this.available = this.tools.length > 0;
    return this.available;
  }

  /**
   * Resolve hostname for a single IP using all available methods
   * @param {string} ip - IP address to query
   * @param {number} timeout - Timeout in milliseconds
   * @returns {Promise<Object|null>} Hostname info or null
   */
  async resolve(ip, timeout = 3000) {
    if (!this.available) {
      await this.checkAvailability();
    }

    // Try each method until one succeeds
    for (const tool of this.tools) {
      try {
        let result = null;

        if (tool === 'smbutil') {
          result = await this._resolveWithSmbutil(ip, timeout);
        } else if (tool === 'nmblookup') {
          result = await this._resolveWithNmblookup(ip, timeout);
        } else if (tool === 'dns-reverse') {
          result = await this._resolveWithDns(ip, timeout);
        }

        if (result && result.hostname) {
          return result;
        }
      } catch {
        // This method failed, try next
        continue;
      }
    }

    return null;
  }

  /**
   * Resolve hostnames for multiple IPs in parallel
   * @param {Array<string>} ips - Array of IP addresses
   * @param {number} timeout - Timeout per query in milliseconds
   * @param {number} concurrency - Max concurrent queries
   * @returns {Promise<Map<string, Object>>} Map of IP to hostname info
   */
  async resolveMany(ips, timeout = 3000, concurrency = 10) {
    const results = new Map();

    // Process in batches for controlled concurrency
    for (let i = 0; i < ips.length; i += concurrency) {
      const batch = ips.slice(i, i + concurrency);
      const promises = batch.map(async (ip) => {
        const result = await this.resolve(ip, timeout);
        if (result) {
          results.set(ip, result);
        }
      });

      await Promise.allSettled(promises);
    }

    return results;
  }

  /**
   * Resolve using smbutil (macOS native) - MOST RELIABLE for Windows
   * @param {string} ip - IP address
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<Object|null>}
   */
  async _resolveWithSmbutil(ip, timeout) {
    let output;

    try {
      // 'status' command queries NetBIOS name service
      output = await executeCommand(`smbutil status ${ip}`, { timeout });
    } catch {
      // If status fails, the host might not be reachable via SMB
      return null;
    }

    // Parse smbutil status output
    // Example output:
    // Using IP address: 192.168.1.100
    // Workgroup: WORKGROUP
    // Server: DESKTOP-ABC123

    const lines = output.split('\n');
    let hostname = null;
    let workgroup = null;

    for (const line of lines) {
      const trimmedLine = line.trim();

      // Match "Server: NAME" - this is the NetBIOS computer name
      const serverMatch = trimmedLine.match(/^Server:\s*(.+)/i);
      if (serverMatch) {
        const value = serverMatch[1].trim();
        // Skip if it looks like an IP address
        if (!value.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
          hostname = value;
        }
      }

      // Match workgroup/domain
      const workgroupMatch = trimmedLine.match(/^(?:Workgroup|Domain):\s*(.+)/i);
      if (workgroupMatch) {
        workgroup = workgroupMatch[1].trim();
      }
    }

    if (hostname) {
      return {
        hostname,
        workgroup,
        source: 'smbutil',
      };
    }

    return null;
  }

  /**
   * Resolve using nmblookup (Samba)
   * @param {string} ip - IP address
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<Object|null>}
   */
  async _resolveWithNmblookup(ip, timeout) {
    // -A: Lookup by IP address (node status query)
    const output = await executeCommand(`nmblookup -A ${ip}`, { timeout });

    // Parse nmblookup output
    // Example:
    // Looking up status of 192.168.1.100
    //   WORKSTATION    <00> -         M <ACTIVE>
    //   WORKGROUP      <00> - <GROUP> M <ACTIVE>
    //   WORKSTATION    <20> -         M <ACTIVE>

    const lines = output.split('\n');
    let hostname = null;
    let workgroup = null;

    for (const line of lines) {
      // Match computer name (type <00>, not GROUP, ACTIVE)
      // Format: "  NAME           <00> -         M <ACTIVE>"
      const nameMatch = line.match(/^\s+([^\s<]+)\s+<00>\s+-\s+[^<]*<ACTIVE>/);
      if (nameMatch && !hostname) {
        hostname = nameMatch[1].trim();
      }

      // Match workgroup/domain (type <00>, GROUP flag)
      const groupMatch = line.match(/^\s+([^\s<]+)\s+<00>\s+-\s+<GROUP>/);
      if (groupMatch) {
        workgroup = groupMatch[1].trim();
      }
    }

    if (hostname) {
      return {
        hostname,
        workgroup,
        source: 'nmblookup',
      };
    }

    return null;
  }

  /**
   * Resolve using reverse DNS lookup (fallback - always available)
   * @param {string} ip - IP address
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<Object|null>}
   */
  async _resolveWithDns(ip, timeout) {
    try {
      // Set a timeout for DNS lookup
      const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('DNS timeout')), timeout)
      );

      const lookupPromise = reverseLookup(ip);
      const hostnames = await Promise.race([lookupPromise, timeoutPromise]);

      if (hostnames && hostnames.length > 0) {
        let hostname = hostnames[0];

        // Clean up the hostname (remove trailing dot)
        hostname = hostname.replace(/\.$/, '');

        // Extract just the computer name (first part before domain)
        const shortName = hostname.split('.')[0];

        return {
          hostname: shortName,
          fqdn: hostname,
          source: 'dns-reverse',
        };
      }
    } catch {
      // DNS lookup failed
    }

    return null;
  }
}
