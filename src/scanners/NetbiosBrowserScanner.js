/**
 * NetBIOS Browser Scanner - Discovers Windows machines via network browsing
 * Uses broadcast-based discovery similar to macOS Finder's Network browser
 */

import { executeCommand } from '../utils/CommandRunner.js';
import BaseScanner from './BaseScanner.js';
import { platform } from 'os';

/**
 * Discovers Windows machines on the network using NetBIOS name service
 * This works even when SMB ports (139/445) are firewalled
 */
export default class NetbiosBrowserScanner extends BaseScanner {
  constructor() {
    super('netbios-browser');
    this.discoveredNames = new Map();
  }

  /**
   * Start NetBIOS browsing scan
   * @param {Object} options - Scan options
   * @param {number} options.timeout - Scan timeout in ms (default 10000)
   * @returns {Promise<void>}
   */
  async start(options = {}) {
    const timeout = options.timeout || 10000;
    this.running = true;
    this.discoveredNames.clear();

    try {
      if (platform() === 'darwin') {
        // macOS: Use smbutil to discover NetBIOS names
        await this._scanWithSmbutil(timeout);
      } else if (platform() === 'linux') {
        // Linux: Use nmblookup if available
        await this._scanWithNmblookup(timeout);
      } else if (platform() === 'win32') {
        // Windows: Use nbtstat to discover NetBIOS names
        await this._scanWithNbtstat(timeout);
      }
    } catch (error) {
      console.warn('NetBIOS browsing failed:', error.message);
    }

    this.running = false;
  }

  /**
   * Scan using macOS smbutil
   * Uses broadcast to discover NetBIOS names on the network
   * @param {number} timeout - Timeout in ms
   */
  async _scanWithSmbutil(timeout) {
    // Method 1: Try to query common workgroup names
    const workgroups = ['WORKGROUP', 'MSHOME', 'HOME', 'OFFICE'];
    
    for (const workgroup of workgroups) {
      try {
        // smbutil lookup broadcasts for the workgroup and waits for responses
        const output = await executeCommand(`smbutil lookup ${workgroup}`, { 
          timeout: Math.min(timeout / workgroups.length, 3000) 
        });
        
        // Parse response - may contain multiple IPs
        // Format: "Got response from x.x.x.x"
        const responseMatches = output.matchAll(/Got response from ([\d.]+)/g);
        for (const match of responseMatches) {
          const ip = match[1];
          if (!this.discoveredNames.has(ip)) {
            this.discoveredNames.set(ip, { ip, possibleWorkgroup: workgroup });
          }
        }
      } catch {
        // Workgroup not found, continue
      }
    }

    // Method 2: Try common Windows hostnames patterns
    // Windows generates names like "DESKTOP-XXXXXXX" or "WIN-XXXXXXX"
    // We can try to look up any recently cached names
    
    // Method 3: Query each discovered IP for its NetBIOS name
    // This is what will actually get us the hostnames
    const ipsToResolve = [];
    for (const [ip] of this.discoveredNames) {
      ipsToResolve.push(ip);
    }

    // Also resolve any IPs that were passed in from ARP scan
    await this._resolveNamesToDevices(timeout);
  }

  /**
   * Resolve NetBIOS names to device info
   * @param {number} timeout - Timeout in ms
   */
  async _resolveNamesToDevices(timeout) {
    const perHostTimeout = Math.min(timeout / Math.max(this.discoveredNames.size, 1), 2000);
    
    for (const [ip, info] of this.discoveredNames) {
      try {
        // Try to get the actual hostname
        const output = await executeCommand(`smbutil status ${ip}`, { 
          timeout: perHostTimeout 
        });
        
        // Parse the status output
        const serverMatch = output.match(/Server:\s*(.+)/i);
        const workgroupMatch = output.match(/(?:Workgroup|Domain):\s*(.+)/i);
        
        if (serverMatch) {
          const hostname = serverMatch[1].trim();
          const workgroup = workgroupMatch ? workgroupMatch[1].trim() : info.possibleWorkgroup;
          
          // Create device record
          const device = {
            ip,
            ipv4: ip,
            hostname,
            workgroup,
            os: 'Windows',
            discoveredVia: ['netbios-browser'],
            source: 'netbios-browser',
            lastSeen: Date.now(),
          };
          
          this.devices.set(ip, device);
        }
      } catch {
        // Status failed (timeout or unreachable), but we still know the IP exists
        // The ARP scan would have found it anyway
      }
    }
  }

  /**
   * Scan using Linux nmblookup
   * @param {number} timeout - Timeout in ms
   */
  async _scanWithNmblookup(timeout) {
    try {
      // Check if nmblookup is available
      await executeCommand('which nmblookup', { timeout: 2000 });
    } catch {
      // nmblookup not available
      return;
    }

    try {
      // Broadcast query for all NetBIOS names
      // nmblookup '*' sends a broadcast and lists all responding machines
      const output = await executeCommand("nmblookup -S '*'", { timeout });
      
      // Parse output - format varies but typically:
      // 192.168.1.100 DESKTOP-ABC123<00>
      const lines = output.split('\n');
      
      for (const line of lines) {
        // Match IP and name
        const match = line.match(/([\d.]+)\s+(\S+)<[\d]+>/);
        if (match) {
          const [, ip, name] = match;
          if (name && !name.startsWith('__')) {
            const device = {
              ip,
              ipv4: ip,
              hostname: name,
              os: 'Windows',
              discoveredVia: ['netbios-browser'],
              source: 'netbios-browser',
              lastSeen: Date.now(),
            };
            this.devices.set(ip, device);
          }
        }
      }
    } catch (error) {
      console.warn('nmblookup broadcast failed:', error.message);
    }
  }

  /**
   * Scan using Windows nbtstat
   * Uses the local NetBIOS name cache and can resolve specific IPs
   * @param {number} timeout - Timeout in ms
   */
  async _scanWithNbtstat(timeout) {
    try {
      // Method 1: Get cached NetBIOS names from local cache
      // nbtstat -c shows the remote name cache
      const cacheOutput = await executeCommand('nbtstat -c', { 
        timeout: Math.min(timeout / 2, 5000) 
      }).catch(() => '');
      
      if (cacheOutput) {
        this._parseNbtstatCache(cacheOutput);
      }

      // Method 2: Get local network connections
      // nbtstat -n shows local NetBIOS names (useful for the local machine)
      const localOutput = await executeCommand('nbtstat -n', { 
        timeout: Math.min(timeout / 2, 5000) 
      }).catch(() => '');
      
      if (localOutput) {
        this._parseNbtstatLocal(localOutput);
      }

      // Method 3: Try to get names from recent network activity
      // The ARP table IPs will be resolved individually via resolveIP
    } catch (error) {
      console.warn('nbtstat scan failed:', error.message);
    }
  }

  /**
   * Parse nbtstat -c (cache) output
   * @param {string} output - Command output
   */
  _parseNbtstatCache(output) {
    const lines = output.split('\n');
    let currentIP = null;
    
    for (const line of lines) {
      // Look for IP address headers
      // Format varies: "192.168.1.100:" or includes the name
      const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      
      // Look for NetBIOS name entries
      // Format: "    COMPUTERNAME      <00>  UNIQUE      Registered"
      const nameMatch = line.match(/^\s+([A-Z0-9_-]+)\s+<([0-9a-fA-F]+)>\s+(UNIQUE|GROUP)/i);
      
      if (ipMatch) {
        currentIP = ipMatch[1];
      }
      
      if (nameMatch && currentIP) {
        const [, name, suffix, type] = nameMatch;
        
        // <00> suffix is the workstation/computer name
        if (suffix === '00' && type.toUpperCase() === 'UNIQUE') {
          const device = {
            ip: currentIP,
            ipv4: currentIP,
            hostname: name.trim(),
            os: 'Windows',
            discoveredVia: ['netbios-browser'],
            source: 'netbios-browser',
            lastSeen: Date.now(),
          };
          this.devices.set(currentIP, device);
        }
      }
    }
  }

  /**
   * Parse nbtstat -n (local names) output
   * @param {string} output - Command output
   */
  _parseNbtstatLocal(output) {
    // This captures the local machine's NetBIOS name
    // which can be useful for network identification
    const lines = output.split('\n');
    
    for (const line of lines) {
      const nameMatch = line.match(/^\s+([A-Z0-9_-]+)\s+<00>\s+UNIQUE/i);
      if (nameMatch) {
        // This is the local computer name - store it if needed
        // Could be useful for self-identification
        break;
      }
    }
  }

  /**
   * Resolve a specific IP address to its NetBIOS name
   * This can be called for IPs discovered by other scanners
   * @param {string} ip - IP address to resolve
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<Object|null>} Device info or null
   */
  async resolveIP(ip, timeout = 2000) {
    try {
      if (platform() === 'darwin') {
        const output = await executeCommand(`smbutil status ${ip}`, { timeout });
        
        const serverMatch = output.match(/Server:\s*(.+)/i);
        const workgroupMatch = output.match(/(?:Workgroup|Domain):\s*(.+)/i);
        
        if (serverMatch) {
          return {
            hostname: serverMatch[1].trim(),
            workgroup: workgroupMatch ? workgroupMatch[1].trim() : null,
            os: 'Windows',
            source: 'netbios-browser',
          };
        }
      } else if (platform() === 'linux') {
        const output = await executeCommand(`nmblookup -A ${ip}`, { timeout });
        
        // Parse nmblookup output
        const lines = output.split('\n');
        for (const line of lines) {
          const match = line.match(/^\s+(\S+)\s+<00>\s+-\s+[^<]*<ACTIVE>/);
          if (match) {
            return {
              hostname: match[1].trim(),
              os: 'Windows',
              source: 'netbios-browser',
            };
          }
        }
      } else if (platform() === 'win32') {
        // Windows: Use nbtstat -A to query remote NetBIOS name table
        const output = await executeCommand(`nbtstat -A ${ip}`, { timeout });
        
        // Parse nbtstat output for computer name
        const lines = output.split('\n');
        for (const line of lines) {
          // Look for <00> UNIQUE entries (computer name)
          const match = line.match(/^\s+([A-Z0-9_-]+)\s+<00>\s+UNIQUE/i);
          if (match) {
            return {
              hostname: match[1].trim(),
              os: 'Windows',
              source: 'netbios-browser',
            };
          }
        }
      }
    } catch {
      // Resolution failed
    }
    return null;
  }

  /**
   * Discover Windows machines by looking up known Windows-style names
   * Windows auto-generates hostnames like WIN-XXXXXXX or DESKTOP-XXXXXXX
   * @param {Array<string>} knownNames - List of hostnames to look up
   * @param {number} timeout - Timeout in ms
   */
  async discoverByNames(knownNames, timeout = 10000) {
    const perNameTimeout = Math.min(timeout / Math.max(knownNames.length, 1), 2000);
    
    for (const name of knownNames) {
      try {
        if (platform() === 'darwin') {
          const output = await executeCommand(`smbutil lookup ${name}`, { 
            timeout: perNameTimeout 
          });
          
          // Parse: "IP address of NAME: x.x.x.x"
          const ipMatches = output.matchAll(/IP address of [^:]+:\s*([\d.]+)/g);
          for (const match of ipMatches) {
            const ip = match[1];
            // Skip loopback and link-local
            if (!ip.startsWith('127.') && !ip.startsWith('169.254.')) {
              const device = {
                ip,
                ipv4: ip,
                hostname: name.toUpperCase(),
                os: 'Windows',
                discoveredVia: ['netbios-browser'],
                source: 'netbios-browser',
                lastSeen: Date.now(),
              };
              this.devices.set(ip, device);
            }
          }
        }
      } catch {
        // Name not found
      }
    }
  }

  getStats() {
    return {
      deviceCount: this.devices.size,
      namesDiscovered: this.discoveredNames.size,
    };
  }
}
