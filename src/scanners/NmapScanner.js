/**
 * Nmap Scanner - Detailed active scanning with OS and service detection
 */

import BaseScanner from './BaseScanner.js';
import { spawnCommand, executeCommand } from '../utils/CommandRunner.js';
import { normalizeMac } from '../utils/NetworkUtils.js';

/**
 * Nmap Scanner for comprehensive device information gathering
 * Performs OS detection, service enumeration, and port scanning
 */
export default class NmapScanner extends BaseScanner {
  constructor(options = {}) {
    super('NmapScanner', options);
    this.processes = [];
  }

  /**
   * Start nmap scanning
   * @param {Object} config - Scan configuration
   * @param {string} config.cidr - CIDR range to scan
   * @param {Array<string>} config.targets - Specific IP targets (optional)
   * @param {boolean} config.detectOS - Enable OS detection
   * @param {boolean} config.fast - Fast scan mode
   * @param {number} config.timeout - Timeout per host
   */
  async start(config) {
    this._onStart();

    try {
      const { cidr, targets, detectOS = true, fast = false, timeout = 30 } = config;

      // Phase 1: Ping sweep to find live hosts
      this._onProgress({ phase: 'ping-sweep', message: 'Discovering live hosts...' });

      const liveHosts = await this._pingSweep(cidr || targets.join(' '));

      this._onProgress({
        phase: 'ping-sweep-complete',
        message: `Found ${liveHosts.length} live hosts`,
        count: liveHosts.length,
      });

      // Phase 2: Detailed scan of live hosts
      if (liveHosts.length > 0 && !fast) {
        this._onProgress({
          phase: 'detailed-scan',
          message: 'Scanning for services and OS...',
        });

        await this._detailedScan(liveHosts, detectOS, timeout);
      }

      this._onComplete();
    } catch (error) {
      this._onError(error);
      throw error;
    }
  }

  /**
   * Stop all nmap processes
   */
  async stop() {
    for (const process of this.processes) {
      if (!process.killed) {
        process.kill('SIGTERM');
      }
    }

    this.processes = [];

    if (this.running) {
      this.running = false;
    }
  }

  /**
   * Perform ping sweep to find live hosts
   * @param {string} target - Target range or hosts
   * @returns {Promise<Array<string>>} Array of live host IPs
   */
  async _pingSweep(target) {
    try {
      // -sn: Ping scan (no port scan)
      // -T4: Aggressive timing
      // --min-rate 300: Minimum packet rate
      const command = `nmap -sn -T4 --min-rate 300 ${target}`;

      const output = await executeCommand(command, { timeout: 60000 });

      // Parse output for live hosts
      const hosts = [];
      const lines = output.split('\n');

      for (const line of lines) {
        // Look for "Nmap scan report for <ip>"
        const match = line.match(/Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);

        if (match) {
          const ip = match[1];
          hosts.push(ip);

          // Add basic device info
          this._addDevice({
            ip,
            lastSeen: new Date().toISOString(),
            source: 'nmap-ping',
          });
        }

        // Look for MAC address in next line
        const macMatch = line.match(/MAC Address: ([\dA-F:]{17}) \(([^)]+)\)/i);
        if (macMatch) {
          const [, mac, vendor] = macMatch;
          // Update the last added device with MAC info
          const lastHost = hosts[hosts.length - 1];
          if (lastHost) {
            this._addDevice({
              ip: lastHost,
              mac: normalizeMac(mac),
              manufacturer: vendor.trim(),
              source: 'nmap-ping',
            });
          }
        }
      }

      return hosts;
    } catch (error) {
      console.error('Ping sweep failed:', error.message);
      return [];
    }
  }

  /**
   * Perform detailed scan on specific hosts
   * @param {Array<string>} hosts - Hosts to scan
   * @param {boolean} detectOS - Enable OS detection
   * @param {number} timeout - Timeout per host
   */
  async _detailedScan(hosts, detectOS, timeout) {
    // Scan hosts in batches to avoid overwhelming the network
    const batchSize = 5;

    for (let i = 0; i < hosts.length; i += batchSize) {
      const batch = hosts.slice(i, i + batchSize);

      // Scan batch in parallel
      const promises = batch.map((host) => this._scanHost(host, detectOS, timeout));

      try {
        await Promise.allSettled(promises);
      } catch (error) {
        console.error('Batch scan error:', error.message);
      }

      // Report progress
      this._onProgress({
        phase: 'detailed-scan',
        scanned: Math.min(i + batchSize, hosts.length),
        total: hosts.length,
      });
    }
  }

  /**
   * Perform detailed scan on a single host
   * @param {string} host - Host IP
   * @param {boolean} detectOS - Enable OS detection
   * @param {number} timeout - Timeout
   * @returns {Promise<Object>} Scan results
   */
  async _scanHost(host, detectOS, timeout) {
    try {
      // Build nmap command
      // -sV: Service version detection
      // -O: OS detection (if enabled)
      // --version-light: Lighter version detection
      // -T4: Aggressive timing
      // --script: Run scripts for better hostname detection
      const args = [
        '-sV',
        '--version-light',
        '-T4',
        `--host-timeout=${timeout}s`,
        '--script=nbstat.nse,smb-os-discovery.nse',
      ];

      if (detectOS) {
        args.push('-O');
      }

      args.push(host);

      const command = `nmap ${args.join(' ')}`;
      const output = await executeCommand(command, { timeout: (timeout + 10) * 1000 });

      // Parse the output
      const deviceInfo = this._parseNmapOutput(output, host);

      // Add to devices
      this._addDevice(deviceInfo);

      return deviceInfo;
    } catch (error) {
      console.error(`Scan failed for ${host}:`, error.message);
      return null;
    }
  }

  /**
   * Parse nmap output for device information
   * @param {string} output - Nmap output
   * @param {string} ip - Host IP
   * @returns {Object} Parsed device info
   */
  _parseNmapOutput(output, ip) {
    const device = {
      ip,
      lastSeen: new Date().toISOString(),
      source: 'nmap-detailed',
      ports: [],
      services: [],
    };

    const lines = output.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Extract MAC address and vendor
      const macMatch = line.match(/MAC Address: ([\dA-F:]{17}) \(([^)]+)\)/i);
      if (macMatch) {
        device.mac = normalizeMac(macMatch[1]);
        device.manufacturer = macMatch[2].trim();
      }

      // Extract hostname from nmap scan report line
      const hostnameMatch = line.match(/Nmap scan report for ([^\s(]+)/);
      if (hostnameMatch && !hostnameMatch[1].match(/^\d/)) {
        device.hostname = hostnameMatch[1];
      }

      // Extract NetBIOS name (Windows hostname)
      // Format: "NetBIOS name: COMPUTERNAME, NetBIOS user: <unknown>, NetBIOS MAC: ..."
      const netbiosMatch = line.match(/NetBIOS name:\s+([^,\s]+)/i);
      if (netbiosMatch && !device.hostname) {
        device.hostname = netbiosMatch[1];
      }

      // Extract Computer name from smb-os-discovery
      // Format: "Computer name: PCNAME"
      const computerMatch = line.match(/Computer name:\s+([^\s]+)/i);
      if (computerMatch && !device.hostname) {
        device.hostname = computerMatch[1];
      }

      // Extract Workgroup/Domain (useful context for Windows machines)
      const workgroupMatch = line.match(/(?:Workgroup|Domain):\s+([^\s]+)/i);
      if (workgroupMatch) {
        device.workgroup = workgroupMatch[1];
      }

      // Extract open ports and services
      const portMatch = line.match(/(\d+)\/(tcp|udp)\s+(open)\s+(\S+)\s*(.*)/);
      if (portMatch) {
        const [, port, protocol, state, service, version] = portMatch;
        device.ports.push(parseInt(port));
        device.services.push({
          port: parseInt(port),
          protocol,
          state,
          service,
          version: version.trim(),
        });
      }

      // Extract OS information
      if (line.includes('OS details:')) {
        device.os = lines[i].replace('OS details:', '').trim();
      } else if (line.includes('Running:')) {
        device.os = lines[i].replace('Running:', '').trim();
      }

      // Extract OS CPE (Common Platform Enumeration)
      const cpeMatch = line.match(/OS CPE: cpe:\/o:([^:]+):([^:]+):?([^:\s]*)/);
      if (cpeMatch) {
        const [, vendor, osName, version] = cpeMatch;
        if (!device.os) {
          device.os = `${vendor} ${osName}`;
        }
        if (version) {
          device.osVersion = version;
        }
      }
    }

    return device;
  }
}
