/**
 * Tcpdump Scanner - Passive network traffic monitoring
 * Captures and analyzes network packets to discover devices and services
 * Enhanced with DHCP/DHCPv6 parsing for hostname extraction and IPv6 support
 */

import BaseScanner from './BaseScanner.js';
import { spawnCommand } from '../utils/CommandRunner.js';
import { normalizeMac, isValidIPv6, getIPv6Type } from '../utils/NetworkUtils.js';
import eventBus, { Events } from '../utils/EventBus.js';

/**
 * Tcpdump Scanner for passive network discovery
 * Monitors network traffic without sending any packets
 * Now with DHCP hostname extraction and IPv6 support
 */
export default class TcpdumpScanner extends BaseScanner {
  constructor(options = {}) {
    super('TcpdumpScanner', options);
    this.process = null;
    this.buffer = '';
    
    // Track DHCP transactions for hostname association
    this.dhcpTransactions = new Map(); // Transaction ID -> {mac, hostname, ip}
    
    // Track hostnames by MAC for enrichment
    this.hostnamesByMac = new Map();
  }

  /**
   * Start tcpdump capture
   * @param {Object} config - Scan configuration
   * @param {string} config.interface - Network interface to monitor
   * @param {number} config.timeout - Capture timeout in seconds (0 = infinite)
   * @param {boolean} config.captureIPv6 - Include IPv6 traffic (default: true)
   * @param {boolean} config.captureDHCP - Capture DHCP for hostname extraction (default: true)
   */
  async start(config) {
    this._onStart();

    try {
      const { 
        interface: iface, 
        timeout = 0,
        captureIPv6 = true,
        captureDHCP = true,
      } = config;

      // Build tcpdump command with enhanced capture
      // -n: Don't resolve hostnames
      // -e: Print link-level header (MAC addresses)
      // -l: Line buffered output
      // -v: Verbose (needed for DHCP details)
      // -s 0: Capture full packets
      const args = ['-n', '-e', '-l', '-v', '-s', '0'];

      if (iface) {
        args.push('-i', iface);
      }

      // Build capture filter
      const filters = [];
      
      // Always capture ARP
      filters.push('arp');
      
      // IPv4 traffic
      filters.push('ip');
      
      // DHCP (ports 67/68)
      if (captureDHCP) {
        filters.push('(udp port 67 or udp port 68)');
      }
      
      // NetBIOS Name Service (port 137) - discovers Windows hostnames
      filters.push('(udp port 137)');
      
      // IPv6 traffic
      if (captureIPv6) {
        filters.push('ip6');
        // DHCPv6 (ports 546/547)
        if (captureDHCP) {
          filters.push('(udp port 546 or udp port 547)');
        }
        // ICMPv6 (neighbor discovery)
        filters.push('icmp6');
      }
      
      // Combine filters with OR
      args.push(filters.join(' or '));

      // Start tcpdump process
      const spawned = spawnCommand('tcpdump', args);
      this.process = spawned.process;

      // Process output line by line
      this.process.stdout.on('data', (data) => {
        this._processOutput(data.toString());
      });

      this.process.stderr.on('data', (data) => {
        // tcpdump writes info to stderr, parse it for useful info
        const line = data.toString().trim();
        if (line && !line.includes('listening on') && !line.includes('packets')) {
          // DHCP verbose output often comes on stderr
          this._processOutput(line);
        }
      });

      this.process.on('error', (error) => {
        this._onError(error);
      });

      this.process.on('close', (code) => {
        if (this.running) {
          this._onComplete();
        }
      });

      // Emit start event
      eventBus.emit(Events.TCPDUMP_START, { scanner: this.name });

      // Set timeout if specified
      if (timeout > 0) {
        setTimeout(() => {
          this.stop();
        }, timeout * 1000);
      }
    } catch (error) {
      this._onError(error);
      throw error;
    }
  }

  /**
   * Stop tcpdump capture
   */
  async stop() {
    if (this.process && !this.process.killed) {
      this.process.kill('SIGTERM');
      eventBus.emit(Events.TCPDUMP_STOP, { scanner: this.name });
    }

    if (this.running) {
      this._onComplete();
    }
  }

  /**
   * Process tcpdump output line by line
   * @param {string} data - Output data chunk
   */
  _processOutput(data) {
    this.buffer += data;

    // Process complete lines
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || ''; // Keep incomplete line in buffer

    for (const line of lines) {
      if (line.trim()) {
        this._parseLine(line);
      }
    }
  }

  /**
   * Parse a single tcpdump output line
   * Enhanced to handle IPv6 and DHCP
   * @param {string} line - Tcpdump output line
   */
  _parseLine(line) {
    try {
      // Check for DHCP hostname (highest priority for hostname discovery)
      if (line.includes('DHCP') || line.includes('BOOTP')) {
        this._parseDHCPLine(line);
        return;
      }

      // Check for DHCPv6
      if (line.includes('dhcp6') || line.includes('DHCPv6')) {
        this._parseDHCPv6Line(line);
        return;
      }

      // Check for ICMPv6 Neighbor Discovery
      if (line.includes('ICMP6') || line.includes('icmp6')) {
        this._parseICMPv6Line(line);
        return;
      }

      // Check for NetBIOS Name Service (port 137)
      if (line.includes('.137') || line.includes('NBT') || line.includes('netbios')) {
        this._parseNetbiosLine(line);
        return;
      }

      // Extract MAC addresses
      const macMatch = line.match(/([\da-fA-F:]{17})\s+>\s+([\da-fA-F:]{17})/);

      // Try to extract IPv4 addresses
      const ipv4Match = line.match(
        /IP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.?\d*\s+>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/
      );

      // Try to extract IPv6 addresses
      const ipv6Match = line.match(
        /IP6\s+([a-fA-F0-9:]+)\s+>\s+([a-fA-F0-9:]+)/
      );

      // Extract protocol
      const protocolMatch = line.match(/ethertype\s+(\w+)/i);

      if (macMatch && (ipv4Match || ipv6Match)) {
        const [, srcMac, dstMac] = macMatch;
        const protocol = protocolMatch ? protocolMatch[1] : 'Unknown';

        if (ipv4Match) {
          const [, srcIp, dstIp] = ipv4Match;

          // Add source device (IPv4)
          this._addDevice({
            ip: srcIp,
            ipv4: srcIp,
            mac: normalizeMac(srcMac),
            hostname: this.hostnamesByMac.get(normalizeMac(srcMac)) || null,
            lastSeen: new Date().toISOString(),
            source: 'tcpdump',
            discoveredVia: ['passive-capture'],
          });

          // Add destination device (if not broadcast)
          if (!dstMac.toLowerCase().startsWith('ff:ff:ff')) {
            this._addDevice({
              ip: dstIp,
              ipv4: dstIp,
              mac: normalizeMac(dstMac),
              hostname: this.hostnamesByMac.get(normalizeMac(dstMac)) || null,
              lastSeen: new Date().toISOString(),
              source: 'tcpdump',
              discoveredVia: ['passive-capture'],
            });
          }
        }

        if (ipv6Match) {
          const [, srcIpv6Full, dstIpv6Full] = ipv6Match;
          
          // Remove port suffix if present
          const srcIpv6 = srcIpv6Full.split('.')[0];
          const dstIpv6 = dstIpv6Full.split('.')[0];

          if (isValidIPv6(srcIpv6)) {
            // Add source device (IPv6)
            this._addDevice({
              mac: normalizeMac(srcMac),
              ipv6: [{
                address: srcIpv6,
                type: getIPv6Type(srcIpv6),
              }],
              hostname: this.hostnamesByMac.get(normalizeMac(srcMac)) || null,
              lastSeen: new Date().toISOString(),
              source: 'tcpdump',
              discoveredVia: ['passive-capture'],
            });
          }

          // Add destination device (if not multicast)
          if (isValidIPv6(dstIpv6) && !dstIpv6.toLowerCase().startsWith('ff')) {
            this._addDevice({
              mac: normalizeMac(dstMac),
              ipv6: [{
                address: dstIpv6,
                type: getIPv6Type(dstIpv6),
              }],
              hostname: this.hostnamesByMac.get(normalizeMac(dstMac)) || null,
              lastSeen: new Date().toISOString(),
              source: 'tcpdump',
              discoveredVia: ['passive-capture'],
            });
          }
        }

        // Emit packet event for further analysis
        eventBus.emit(Events.TCPDUMP_PACKET, {
          srcMac: normalizeMac(srcMac),
          dstMac: normalizeMac(dstMac),
          srcIp: ipv4Match?.[1],
          dstIp: ipv4Match?.[2],
          srcIpv6: ipv6Match?.[1],
          dstIpv6: ipv6Match?.[2],
          protocol,
          raw: line,
        });
      }
    } catch (error) {
      // Silently ignore parse errors for malformed lines
    }
  }

  /**
   * Parse DHCP line for hostname extraction
   * DHCP packets contain client hostname (option 12) and other useful info
   * @param {string} line - Tcpdump line containing DHCP
   */
  _parseDHCPLine(line) {
    try {
      // Extract MAC address
      const macMatch = line.match(/([\da-fA-F:]{17})/);
      
      // Extract hostname from DHCP option 12 (Hostname)
      // Format: "Hostname Option 12, length X: hostname"
      // Or: "Host Name "hostname""
      const hostnameMatch = line.match(/(?:Hostname|Host\s*Name)[^"]*"([^"]+)"/i) ||
                            line.match(/Hostname[^:]+:\s*(\S+)/i) ||
                            line.match(/option 12[^:]*:\s*"?([^"\s]+)"?/i);

      // Extract client identifier
      const clientIdMatch = line.match(/Client-ID[^:]*:\s*([^\s,]+)/i);

      // Extract requested IP
      const requestedIpMatch = line.match(/Requested-IP[^:]*:\s*(\d+\.\d+\.\d+\.\d+)/i);

      // Extract assigned IP (from DHCP ACK/OFFER)
      const yourIpMatch = line.match(/Your-IP[^:]*:\s*(\d+\.\d+\.\d+\.\d+)/i);

      // Extract vendor class (can reveal device type)
      const vendorMatch = line.match(/Vendor-Class[^:]*:\s*"?([^"]+)"?/i);

      if (macMatch) {
        const mac = normalizeMac(macMatch[1]);
        
        // Store hostname by MAC for future reference
        if (hostnameMatch && hostnameMatch[1]) {
          const hostname = hostnameMatch[1].trim();
          if (hostname && hostname !== '(none)' && !hostname.match(/^[\d.]+$/)) {
            this.hostnamesByMac.set(mac, hostname);
            
            // Update any existing device with this MAC
            const device = this.devices.get(mac);
            if (device && !device.hostname) {
              device.hostname = hostname;
              eventBus.emit(Events.DEVICE_UPDATED, { device, scanner: this.name });
            }
          }
        }

        // Build device data
        const deviceData = {
          mac,
          lastSeen: new Date().toISOString(),
          source: 'dhcp',
          discoveredVia: ['dhcp'],
        };

        if (hostnameMatch?.[1]) {
          deviceData.hostname = hostnameMatch[1].trim();
        }

        if (yourIpMatch?.[1]) {
          deviceData.ip = yourIpMatch[1];
          deviceData.ipv4 = yourIpMatch[1];
        } else if (requestedIpMatch?.[1]) {
          deviceData.ip = requestedIpMatch[1];
          deviceData.ipv4 = requestedIpMatch[1];
        }

        if (vendorMatch?.[1]) {
          // Store vendor class as a hint for device type
          deviceData.dhcpVendorClass = vendorMatch[1].trim();
        }

        this._addDevice(deviceData);
      }
    } catch {
      // Ignore DHCP parse errors
    }
  }

  /**
   * Parse DHCPv6 line for hostname and IPv6 extraction
   * @param {string} line - Tcpdump line containing DHCPv6
   */
  _parseDHCPv6Line(line) {
    try {
      // Extract MAC and IPv6 addresses
      const macMatch = line.match(/([\da-fA-F:]{17})/);
      const ipv6Match = line.match(/([a-fA-F0-9:]+:+[a-fA-F0-9:]+)/g);

      // Extract FQDN option (option 39)
      const fqdnMatch = line.match(/FQDN[^:]*:\s*"?([^"\s,]+)"?/i) ||
                        line.match(/Client\s*FQDN[^:]*:\s*"?([^"\s,]+)"?/i);

      if (macMatch && ipv6Match) {
        const mac = normalizeMac(macMatch[1]);
        
        // Filter out link-local and find global/ULA addresses
        const validIpv6 = ipv6Match
          .filter(ip => isValidIPv6(ip) && !ip.toLowerCase().startsWith('fe80'))
          .map(ip => ({
            address: ip,
            type: getIPv6Type(ip),
          }));

        if (validIpv6.length > 0 || fqdnMatch) {
          const deviceData = {
            mac,
            lastSeen: new Date().toISOString(),
            source: 'dhcpv6',
            discoveredVia: ['dhcpv6'],
          };

          if (validIpv6.length > 0) {
            deviceData.ipv6 = validIpv6;
          }

          if (fqdnMatch?.[1]) {
            const fqdn = fqdnMatch[1].trim();
            deviceData.fqdn = fqdn;
            deviceData.hostname = fqdn.split('.')[0];
            this.hostnamesByMac.set(mac, deviceData.hostname);
          }

          this._addDevice(deviceData);
        }
      }
    } catch {
      // Ignore DHCPv6 parse errors
    }
  }

  /**
   * Parse ICMPv6 line for neighbor discovery
   * @param {string} line - Tcpdump line containing ICMPv6
   */
  _parseICMPv6Line(line) {
    try {
      // Look for Neighbor Advertisement or Neighbor Solicitation
      if (!line.includes('neighbor') && !line.includes('NA') && !line.includes('NS')) {
        return;
      }

      // Extract MAC address
      const macMatch = line.match(/([\da-fA-F:]{17})/);
      
      // Extract IPv6 addresses
      const ipv6Match = line.match(/([a-fA-F0-9:]+:+[a-fA-F0-9:]+)/g);

      // Extract target address from neighbor advertisement
      const targetMatch = line.match(/tgt is\s+([a-fA-F0-9:]+)/i);

      if (macMatch && (ipv6Match || targetMatch)) {
        const mac = normalizeMac(macMatch[1]);
        const addresses = [];

        if (targetMatch && isValidIPv6(targetMatch[1])) {
          addresses.push({
            address: targetMatch[1],
            type: getIPv6Type(targetMatch[1]),
          });
        }

        if (ipv6Match) {
          for (const ip of ipv6Match) {
            if (isValidIPv6(ip) && !addresses.some(a => a.address === ip)) {
              addresses.push({
                address: ip,
                type: getIPv6Type(ip),
              });
            }
          }
        }

        if (addresses.length > 0) {
          this._addDevice({
            mac,
            ipv6: addresses,
            lastSeen: new Date().toISOString(),
            source: 'icmpv6',
            discoveredVia: ['ndp'],
          });
        }
      }
    } catch {
      // Ignore ICMPv6 parse errors
    }
  }

  /**
   * Parse NetBIOS Name Service line for Windows hostname discovery
   * NetBIOS broadcasts contain Windows computer names
   * @param {string} line - Tcpdump line containing NetBIOS traffic
   */
  _parseNetbiosLine(line) {
    try {
      // Extract MAC address
      const macMatch = line.match(/([\da-fA-F:]{17})/);
      
      // Extract source IP
      const ipMatch = line.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.137/);
      
      // NetBIOS name registration/query packets contain the computer name
      // Format varies but often: "NBT ... Name=COMPUTERNAME<00>"
      // Or: "NB DESKTOP-ABC123"
      const nameMatch = line.match(/Name[=:]?\s*"?([A-Z0-9_-]+)"?\s*<[0-9a-fA-F]+>/i) ||
                        line.match(/NB\s+([A-Z0-9_-]+)\s/i) ||
                        line.match(/NBT[^>]*>\s+([A-Z0-9_-]+)\s/i) ||
                        line.match(/NBNS[^"]*"([^"]+)"/i);

      if (macMatch && ipMatch && nameMatch) {
        const mac = normalizeMac(macMatch[1]);
        const ip = ipMatch[1];
        const hostname = nameMatch[1].trim().toUpperCase();
        
        // Skip broadcast names and group names
        if (hostname && 
            hostname !== 'WORKGROUP' && 
            hostname !== 'MSHOME' &&
            !hostname.startsWith('_') &&
            hostname.length > 1) {
          
          // Store hostname by MAC
          this.hostnamesByMac.set(mac, hostname);
          
          // Create/update device
          this._addDevice({
            ip,
            ipv4: ip,
            mac,
            hostname,
            os: 'Windows',
            lastSeen: new Date().toISOString(),
            source: 'netbios',
            discoveredVia: ['netbios'],
          });
        }
      } else if (macMatch && nameMatch) {
        // We got the name but not the IP (rare case)
        const mac = normalizeMac(macMatch[1]);
        const hostname = nameMatch[1].trim().toUpperCase();
        
        if (hostname && 
            hostname !== 'WORKGROUP' && 
            hostname !== 'MSHOME' &&
            !hostname.startsWith('_') &&
            hostname.length > 1) {
          this.hostnamesByMac.set(mac, hostname);
        }
      }
    } catch {
      // Ignore NetBIOS parse errors
    }
  }

  /**
   * Get hostname for a MAC address (from DHCP snooping)
   * @param {string} mac - MAC address
   * @returns {string|null} Hostname or null
   */
  getHostnameByMac(mac) {
    return this.hostnamesByMac.get(normalizeMac(mac)) || null;
  }
}
