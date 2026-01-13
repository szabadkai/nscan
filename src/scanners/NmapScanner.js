/**
 * Nmap Scanner - Detailed active scanning with OS and service detection
 * Enhanced with IPv6 support and configurable scan levels
 */

import BaseScanner from './BaseScanner.js';
import { spawnCommand, executeCommand } from '../utils/CommandRunner.js';
import { normalizeMac, isValidIPv6, getIPv6Type } from '../utils/NetworkUtils.js';

/**
 * Scan level configurations
 */
const SCAN_LEVELS = {
  quick: {
    ports: '22,80,443',
    timing: 'T4',
    osDetection: false,
    versionIntensity: 0,
    scripts: [],
    hostTimeout: 10,
  },
  standard: {
    ports: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
    timing: 'T4',
    osDetection: true,
    osGuess: false,
    versionIntensity: 2,
    scripts: ['smb-os-discovery', 'rdp-ntlm-info'],
    hostTimeout: 30,
  },
  thorough: {
    ports: 'top1000', // Will use --top-ports 1000
    timing: 'T3',
    osDetection: true,
    osGuess: true,
    versionIntensity: 5,
    scripts: ['smb-os-discovery', 'smb2-security-mode', 'rdp-ntlm-info', 'http-server-header', 'ssh-hostkey'],
    hostTimeout: 90,
  },
};

/**
 * Nmap Scanner for comprehensive device information gathering
 * Performs OS detection, service enumeration, and port scanning
 * Now with IPv6 support and configurable scan levels
 */
export default class NmapScanner extends BaseScanner {
  constructor(options = {}) {
    super('NmapScanner', options);
    this.processes = [];
    this.scanLevel = options.scanLevel || 'standard';
  }

  /**
   * Start nmap scanning
   * @param {Object} config - Scan configuration
   * @param {string} config.cidr - CIDR range to scan (IPv4)
   * @param {Array<string>} config.targets - Specific IP targets (optional)
   * @param {Array<string>} config.ipv6Targets - IPv6 targets to scan
   * @param {boolean} config.detectOS - Enable OS detection
   * @param {boolean} config.fast - Fast scan mode
   * @param {number} config.timeout - Timeout per host
   * @param {string} config.scanLevel - Scan level (quick/standard/thorough)
   * @param {string} config.interface - Network interface for IPv6 scans
   */
  async start(config) {
    this._onStart();

    try {
      const {
        cidr,
        targets,
        ipv6Targets = [],
        detectOS = true,
        fast = false,
        timeout = 30,
        scanLevel = this.scanLevel,
        interface: iface,
      } = config;

      // Use quick scan level if fast mode
      this.scanLevel = fast ? 'quick' : scanLevel;

      // Phase 1: IPv4 Ping sweep to find live hosts
      this._onProgress({ phase: 'ping-sweep', message: 'Discovering live IPv4 hosts...' });

      const liveHosts = await this._pingSweep(cidr || targets?.join(' '), false);

      this._onProgress({
        phase: 'ping-sweep-complete',
        message: `Found ${liveHosts.length} live IPv4 hosts`,
        count: liveHosts.length,
      });

      // Phase 1b: IPv6 discovery if targets provided or interface specified
      let liveIPv6Hosts = [];
      if (ipv6Targets.length > 0) {
        this._onProgress({ phase: 'ipv6-discovery', message: 'Scanning IPv6 targets...' });
        liveIPv6Hosts = await this._discoverIPv6Hosts(ipv6Targets, iface);
        this._onProgress({
          phase: 'ipv6-discovery-complete',
          message: `Found ${liveIPv6Hosts.length} IPv6 hosts`,
          count: liveIPv6Hosts.length,
        });
      }

      // Phase 2: Detailed scan of live hosts (if not in quick mode)
      if (this.scanLevel !== 'quick') {
        if (liveHosts.length > 0) {
          this._onProgress({
            phase: 'detailed-scan',
            message: 'Scanning IPv4 hosts for services and OS...',
          });
          await this._detailedScan(liveHosts, detectOS, timeout, false);
        }

        if (liveIPv6Hosts.length > 0) {
          this._onProgress({
            phase: 'detailed-scan-ipv6',
            message: 'Scanning IPv6 hosts for services...',
          });
          await this._detailedScan(liveIPv6Hosts, detectOS, timeout, true);
        }
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
   * @param {boolean} isIPv6 - Whether this is an IPv6 scan
   * @returns {Promise<Array<string>>} Array of live host IPs
   */
  async _pingSweep(target, isIPv6 = false) {
    try {
      // -sn: Ping scan (no port scan)
      // -T4: Aggressive timing
      // --min-rate 300: Minimum packet rate
      const args = ['-sn', '-T4', '--min-rate', '300'];
      
      if (isIPv6) {
        args.unshift('-6');
      }
      
      args.push(target);
      
      const command = `nmap ${args.join(' ')}`;
      const output = await executeCommand(command, { timeout: 60000 });

      // Parse output for live hosts
      const hosts = [];
      const lines = output.split('\n');

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        
        // Look for "Nmap scan report for <ip>" (IPv4)
        const ipv4Match = line.match(/Nmap scan report for (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        
        // Look for IPv6 addresses
        const ipv6Match = line.match(/Nmap scan report for ([a-fA-F0-9:]+(?:%\w+)?)/);

        if (ipv4Match) {
          const ip = ipv4Match[1];
          hosts.push(ip);

          // Add basic device info
          this._addDevice({
            ip,
            ipv4: ip,
            lastSeen: new Date().toISOString(),
            source: 'nmap-ping',
            discoveredVia: ['nmap-ping'],
          });
        } else if (ipv6Match && isValidIPv6(ipv6Match[1].split('%')[0])) {
          const ip = ipv6Match[1];
          hosts.push(ip);

          this._addDevice({
            ipv6: [{
              address: ip.split('%')[0],
              type: getIPv6Type(ip.split('%')[0]),
            }],
            lastSeen: new Date().toISOString(),
            source: 'nmap-ping',
            discoveredVia: ['nmap-ping'],
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
              ip: isIPv6 ? undefined : lastHost,
              ipv6: isIPv6 ? [{
                address: lastHost.split('%')[0],
                type: getIPv6Type(lastHost.split('%')[0]),
              }] : undefined,
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
   * Discover IPv6 hosts on local network using multicast
   * @param {Array<string>} targets - Known IPv6 targets or empty for discovery
   * @param {string} iface - Network interface
   * @returns {Promise<Array<string>>} Discovered IPv6 hosts
   */
  async _discoverIPv6Hosts(targets, iface) {
    const hosts = [];

    try {
      if (targets.length > 0) {
        // Scan provided targets
        for (const target of targets) {
          hosts.push(target);
        }
      } else if (iface) {
        // Use nmap's IPv6 multicast discovery scripts
        const command = `nmap -6 --script=targets-ipv6-multicast-echo,targets-ipv6-multicast-slaac -e ${iface}`;
        const output = await executeCommand(command, { timeout: 30000 }).catch(() => '');
        
        // Parse discovered hosts
        const ipv6Matches = output.matchAll(/([a-fA-F0-9:]+(?:%\w+)?)/g);
        for (const match of ipv6Matches) {
          const ip = match[1].split('%')[0];
          if (isValidIPv6(ip) && !ip.startsWith('ff') && !hosts.includes(ip)) {
            hosts.push(ip);
          }
        }
      }
    } catch (error) {
      console.warn('IPv6 discovery failed:', error.message);
    }

    return hosts;
  }

  /**
   * Perform detailed scan on specific hosts
   * @param {Array<string>} hosts - Hosts to scan
   * @param {boolean} detectOS - Enable OS detection
   * @param {number} timeout - Timeout per host
   * @param {boolean} isIPv6 - Whether scanning IPv6 hosts
   */
  async _detailedScan(hosts, detectOS, timeout, isIPv6 = false) {
    const levelConfig = SCAN_LEVELS[this.scanLevel] || SCAN_LEVELS.standard;
    
    // Scan hosts in batches to avoid overwhelming the network
    const batchSize = 15;

    for (let i = 0; i < hosts.length; i += batchSize) {
      const batch = hosts.slice(i, i + batchSize);

      // Scan batch in parallel
      const promises = batch.map((host) => 
        this._scanHost(host, detectOS, timeout, isIPv6, levelConfig)
      );

      try {
        await Promise.allSettled(promises);
      } catch (error) {
        console.error('Batch scan error:', error.message);
      }

      // Report progress
      this._onProgress({
        phase: isIPv6 ? 'detailed-scan-ipv6' : 'detailed-scan',
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
   * @param {boolean} isIPv6 - Whether this is an IPv6 host
   * @param {Object} levelConfig - Scan level configuration
   * @returns {Promise<Object>} Scan results
   */
  async _scanHost(host, detectOS, timeout, isIPv6, levelConfig) {
    try {
      const args = this._buildDetailedScanArgs(host, detectOS, timeout, isIPv6, levelConfig);
      const command = `nmap ${args.join(' ')}`;
      const output = await executeCommand(command, { timeout: (timeout + 10) * 1000 });

      // Parse the output
      const deviceInfo = this._parseNmapOutput(output, host, isIPv6);

      // Add to devices
      this._addDevice(deviceInfo);

      return deviceInfo;
    } catch (error) {
      console.error(`Scan failed for ${host}:`, error.message);
      return null;
    }
  }

  /**
   * Build nmap arguments for detailed scan based on scan level
   * @param {string} host - Target host
   * @param {boolean} detectOS - Enable OS detection
   * @param {number} timeout - Timeout per host
   * @param {boolean} isIPv6 - IPv6 target
   * @param {Object} levelConfig - Scan level configuration
   * @returns {Array<string>} Nmap arguments
   */
  _buildDetailedScanArgs(host, detectOS, timeout, isIPv6, levelConfig) {
    const args = [];

    // IPv6 flag
    if (isIPv6) {
      args.push('-6');
    }

    // Port specification
    if (levelConfig.ports === 'top1000') {
      args.push('--top-ports', '1000');
    } else {
      args.push('-p', levelConfig.ports);
    }

    // Service version detection
    args.push('-sV');
    if (levelConfig.versionIntensity > 0) {
      args.push(`--version-intensity=${levelConfig.versionIntensity}`);
    } else {
      args.push('--version-light');
    }

    // Timing
    args.push(`-${levelConfig.timing}`);
    args.push(`--host-timeout=${levelConfig.hostTimeout || timeout}s`);

    // Scripts
    if (levelConfig.scripts && levelConfig.scripts.length > 0) {
      args.push(`--script=${levelConfig.scripts.join(',')}`);
    }

    // OS detection
    if (detectOS && levelConfig.osDetection) {
      args.push('-O');
      if (levelConfig.osGuess) {
        args.push('--osscan-guess');
      } else {
        args.push('--osscan-limit');
      }
    }

    args.push(host);

    return args;
  }

  /**
   * Parse nmap output for device information
   * Enhanced with IPv6 support
   * @param {string} output - Nmap output
   * @param {string} ip - Host IP
   * @param {boolean} isIPv6 - Whether this is an IPv6 host
   * @returns {Object} Parsed device info
   */
  _parseNmapOutput(output, ip, isIPv6) {
    const device = {
      lastSeen: new Date().toISOString(),
      source: 'nmap-detailed',
      discoveredVia: ['nmap'],
      ports: [],
      services: [],
    };

    // Set IP appropriately
    if (isIPv6) {
      const cleanIP = ip.split('%')[0];
      device.ipv6 = [{
        address: cleanIP,
        type: getIPv6Type(cleanIP),
      }];
    } else {
      device.ip = ip;
      device.ipv4 = ip;
    }

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
      if (hostnameMatch && !hostnameMatch[1].match(/^\d/) && !hostnameMatch[1].includes(':')) {
        device.hostname = hostnameMatch[1];
      }

      // Extract NetBIOS name (Windows hostname)
      const netbiosMatch = line.match(/NetBIOS name:\s+([^,\s]+)/i);
      if (netbiosMatch && !device.hostname) {
        device.hostname = netbiosMatch[1];
      }

      // Extract Computer name from smb-os-discovery
      const computerMatch = line.match(/Computer name:\s+([^\s]+)/i);
      if (computerMatch && !device.hostname) {
        device.hostname = computerMatch[1];
      }

      // Extract hostname from RDP NTLM info
      const rdpTargetMatch = line.match(/Target_Name:\s*([^\s]+)/i);
      if (rdpTargetMatch && !device.hostname) {
        device.hostname = rdpTargetMatch[1];
      }

      // Extract DNS computer name from RDP NTLM info
      const rdpDnsMatch = line.match(/DNS_Computer_Name:\s*([^\s]+)/i);
      if (rdpDnsMatch) {
        const fqdn = rdpDnsMatch[1];
        if (!device.hostname) {
          device.hostname = fqdn.split('.')[0];
        }
        device.fqdn = fqdn;
      }

      // Extract domain from RDP NTLM info
      const rdpDomainMatch = line.match(/DNS_Domain_Name:\s*([^\s]+)/i);
      if (rdpDomainMatch && !device.workgroup) {
        device.workgroup = rdpDomainMatch[1];
      }

      // Extract Workgroup/Domain
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

      // Extract SSH hostkey info for fingerprinting
      const sshMatch = line.match(/ssh-hostkey:.*?(\d+)\s+([\da-f:]+)/i);
      if (sshMatch) {
        device.sshFingerprint = sshMatch[2];
      }
    }

    return device;
  }

  /**
   * Set the scan level
   * @param {string} level - Scan level (quick/standard/thorough)
   */
  setScanLevel(level) {
    if (SCAN_LEVELS[level]) {
      this.scanLevel = level;
    } else {
      console.warn(`Unknown scan level: ${level}, using 'standard'`);
      this.scanLevel = 'standard';
    }
  }
}

export { SCAN_LEVELS };
