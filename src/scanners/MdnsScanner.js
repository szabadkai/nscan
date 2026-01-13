/**
 * mDNS Scanner - Multicast DNS / Bonjour service discovery
 * Discovers devices announcing services via mDNS (Apple, Chromecast, printers, IoT)
 */

import BaseScanner from './BaseScanner.js';
import { executeCommand, commandExists, spawnCommand } from '../utils/CommandRunner.js';
import { normalizeMac, isValidIP, isValidIPv6, getIPv6Type } from '../utils/NetworkUtils.js';
import eventBus, { Events } from '../utils/EventBus.js';

/**
 * Common mDNS service types to browse
 */
const MDNS_SERVICE_TYPES = [
  '_services._dns-sd._udp',  // Meta-query for all services
  '_http._tcp',              // Web servers
  '_https._tcp',             // Secure web servers
  '_ssh._tcp',               // SSH servers
  '_sftp-ssh._tcp',          // SFTP
  '_smb._tcp',               // SMB/Windows shares
  '_afpovertcp._tcp',        // Apple File Sharing
  '_printer._tcp',           // Printers
  '_ipp._tcp',               // Internet Printing Protocol
  '_pdl-datastream._tcp',    // Printer data stream
  '_scanner._tcp',           // Scanners
  '_airplay._tcp',           // AirPlay (Apple TV, speakers)
  '_raop._tcp',              // Remote Audio Output (AirPlay audio)
  '_spotify-connect._tcp',   // Spotify Connect
  '_googlecast._tcp',        // Chromecast
  '_homekit._tcp',           // HomeKit devices
  '_hap._tcp',               // HomeKit Accessory Protocol
  '_companion-link._tcp',    // Apple device pairing
  '_sleep-proxy._udp',       // Sleep Proxy (Apple)
  '_workstation._tcp',       // Workstations
  '_device-info._tcp',       // Device info
  '_rdlink._tcp',            // Remote Desktop
  '_nvstream._tcp',          // NVIDIA GameStream
  '_daap._tcp',              // iTunes/Music sharing
  '_dacp._tcp',              // iTunes Remote
  '_touch-able._tcp',        // Touch Remote
  '_appletv-v2._tcp',        // Apple TV
  '_mediaremotetv._tcp',     // Apple TV Remote
  '_mqtt._tcp',              // MQTT (IoT)
  '_hue._tcp',               // Philips Hue
  '_sonos._tcp',             // Sonos
  '_esphomelib._tcp',        // ESPHome devices
];

/**
 * mDNS Scanner for service discovery
 * Uses native tools (dns-sd on macOS, avahi-browse on Linux)
 */
export default class MdnsScanner extends BaseScanner {
  constructor(options = {}) {
    super('MdnsScanner', options);
    this.platform = process.platform;
    this.processes = [];
    this.discoveredServices = new Map(); // Track services by hostname
    this.scanTimeout = options.timeout || 10000; // 10 second default
  }

  /**
   * Start mDNS service discovery
   * @param {Object} config - Scan configuration
   * @param {number} config.timeout - Discovery timeout in ms
   * @param {Array<string>} config.serviceTypes - Service types to browse (optional)
   */
  async start(config = {}) {
    this._onStart();

    const timeout = config.timeout || this.scanTimeout;
    const serviceTypes = config.serviceTypes || MDNS_SERVICE_TYPES;

    try {
      if (this.platform === 'darwin') {
        await this._scanWithDnsSd(serviceTypes, timeout);
      } else if (this.platform === 'linux') {
        await this._scanWithAvahi(serviceTypes, timeout);
      } else if (this.platform === 'win32') {
        // Windows doesn't have built-in mDNS tools
        // Could use dns-sd if Bonjour Print Services is installed
        const hasDnsSd = await commandExists('dns-sd');
        if (hasDnsSd) {
          await this._scanWithDnsSd(serviceTypes, timeout);
        } else {
          console.warn('mDNS scanning requires Bonjour Print Services on Windows');
        }
      }

      // Convert discovered services to devices
      this._processDiscoveredServices();
      
      this._onComplete();
    } catch (error) {
      this._onError(error);
      throw error;
    }
  }

  /**
   * Stop all mDNS discovery processes
   */
  async stop() {
    for (const proc of this.processes) {
      if (proc && !proc.killed) {
        proc.kill('SIGTERM');
      }
    }
    this.processes = [];

    if (this.running) {
      this.running = false;
    }
  }

  /**
   * Scan using dns-sd command (macOS/Windows with Bonjour)
   * @param {Array<string>} serviceTypes - Service types to browse
   * @param {number} timeout - Timeout in ms
   */
  async _scanWithDnsSd(serviceTypes, timeout) {
    // First, do a meta-query to find all available service types
    const allServices = await this._browseServiceTypes(timeout / 2);
    
    // Merge discovered service types with our known list
    const typesToBrowse = [...new Set([...serviceTypes, ...allServices])];
    
    // Browse each service type
    const browsePromises = typesToBrowse.slice(0, 20).map(async (serviceType) => {
      try {
        await this._browseDnsSdService(serviceType, timeout / 2);
      } catch {
        // Ignore individual service browse failures
      }
    });

    await Promise.allSettled(browsePromises);
  }

  /**
   * Browse for all service types using dns-sd
   * @param {number} timeout - Timeout in ms
   * @returns {Promise<Array<string>>} Discovered service types
   */
  async _browseServiceTypes(timeout) {
    return new Promise((resolve) => {
      const services = [];
      
      try {
        const spawned = spawnCommand('dns-sd', ['-B', '_services._dns-sd._udp', 'local']);
        this.processes.push(spawned.process);

        const timer = setTimeout(() => {
          spawned.process.kill('SIGTERM');
          resolve(services);
        }, timeout);

        spawned.process.stdout.on('data', (data) => {
          const lines = data.toString().split('\n');
          for (const line of lines) {
            // Parse: Browsing for _services._dns-sd._udp
            // Instance Name: _googlecast
            const match = line.match(/(\d+:\d+:\d+\.\d+)\s+\w+\s+\w+\s+\w+\s+(\S+)\s+(\S+)/);
            if (match) {
              const [, , serviceType, domain] = match;
              if (serviceType && serviceType.startsWith('_')) {
                services.push(serviceType);
              }
            }
          }
        });

        spawned.process.on('close', () => {
          clearTimeout(timer);
          resolve(services);
        });

        spawned.process.on('error', () => {
          clearTimeout(timer);
          resolve(services);
        });
      } catch {
        resolve(services);
      }
    });
  }

  /**
   * Browse a specific service type using dns-sd
   * @param {string} serviceType - Service type to browse
   * @param {number} timeout - Timeout in ms
   */
  async _browseDnsSdService(serviceType, timeout) {
    return new Promise((resolve) => {
      try {
        const spawned = spawnCommand('dns-sd', ['-B', serviceType, 'local']);
        this.processes.push(spawned.process);

        const timer = setTimeout(() => {
          spawned.process.kill('SIGTERM');
          resolve();
        }, timeout);

        spawned.process.stdout.on('data', (data) => {
          this._parseDnsSdBrowseOutput(data.toString(), serviceType);
        });

        spawned.process.on('close', () => {
          clearTimeout(timer);
          resolve();
        });

        spawned.process.on('error', () => {
          clearTimeout(timer);
          resolve();
        });
      } catch {
        resolve();
      }
    });
  }

  /**
   * Parse dns-sd browse output
   * @param {string} output - Command output
   * @param {string} serviceType - Service type being browsed
   */
  _parseDnsSdBrowseOutput(output, serviceType) {
    const lines = output.split('\n');

    for (const line of lines) {
      // Skip header lines
      if (line.includes('Browsing') || line.includes('DATE') || !line.trim()) {
        continue;
      }

      // Parse browse results
      // Format: Timestamp  A/R Flags if Domain  Service Type  Instance Name
      const match = line.match(/\d+:\d+:\d+\.\d+\s+(Add|Rmv)\s+\d+\s+\d+\s+(\S+)\.\s+(\S+)\.\s+(.+)/);
      if (match) {
        const [, action, domain, type, instanceName] = match;
        
        if (action === 'Add') {
          // Resolve this instance to get IP/hostname
          this._resolveDnsSdInstance(instanceName.trim(), serviceType, domain);
        }
      }
    }
  }

  /**
   * Resolve a dns-sd instance to get its address
   * @param {string} instanceName - Instance name
   * @param {string} serviceType - Service type
   * @param {string} domain - Domain
   */
  async _resolveDnsSdInstance(instanceName, serviceType, domain) {
    try {
      // Quick resolve with short timeout
      const output = await executeCommand(
        `dns-sd -L "${instanceName}" ${serviceType} ${domain}`,
        { timeout: 3000 }
      ).catch(() => '');

      if (output) {
        // Parse resolve output for hostname and port
        const hostMatch = output.match(/can be reached at\s+(\S+):(\d+)/);
        if (hostMatch) {
          const [, hostname, port] = hostMatch;
          this._addServiceToMap(instanceName, serviceType, hostname, parseInt(port), {});
        }
      }

      // Also try to get the IP address
      const lookupOutput = await executeCommand(
        `dns-sd -G v4v6 "${instanceName}.local"`,
        { timeout: 2000 }
      ).catch(() => '');

      if (lookupOutput) {
        this._parseAddressLookup(lookupOutput, instanceName);
      }
    } catch {
      // Ignore resolve failures
    }
  }

  /**
   * Parse address lookup output
   * @param {string} output - Lookup output
   * @param {string} instanceName - Instance name
   */
  _parseAddressLookup(output, instanceName) {
    const lines = output.split('\n');
    
    for (const line of lines) {
      // Parse IPv4 or IPv6 address
      const ipv4Match = line.match(/(\d+\.\d+\.\d+\.\d+)/);
      const ipv6Match = line.match(/([a-fA-F0-9:]+:+[a-fA-F0-9:]+)/);

      if (ipv4Match && isValidIP(ipv4Match[1])) {
        const existing = this.discoveredServices.get(instanceName) || {};
        existing.ipv4 = ipv4Match[1];
        this.discoveredServices.set(instanceName, existing);
      }

      if (ipv6Match && isValidIPv6(ipv6Match[1])) {
        const existing = this.discoveredServices.get(instanceName) || {};
        existing.ipv6 = existing.ipv6 || [];
        if (!existing.ipv6.some(v6 => v6.address === ipv6Match[1])) {
          existing.ipv6.push({
            address: ipv6Match[1],
            type: getIPv6Type(ipv6Match[1]),
          });
        }
        this.discoveredServices.set(instanceName, existing);
      }
    }
  }

  /**
   * Scan using avahi-browse (Linux)
   * @param {Array<string>} serviceTypes - Service types to browse
   * @param {number} timeout - Timeout in ms
   */
  async _scanWithAvahi(serviceTypes, timeout) {
    try {
      // Check if avahi-browse is available
      const hasAvahi = await commandExists('avahi-browse');
      if (!hasAvahi) {
        console.warn('avahi-browse not found. Install avahi-utils for mDNS discovery.');
        return;
      }

      // Use avahi-browse to discover all services
      // -a: all services, -t: terminate after browsing, -r: resolve, -p: parseable
      const output = await executeCommand(
        'avahi-browse -a -t -r -p',
        { timeout }
      ).catch(() => '');

      if (output) {
        this._parseAvahiOutput(output);
      }
    } catch (error) {
      console.warn('avahi-browse failed:', error.message);
    }
  }

  /**
   * Parse avahi-browse parseable output
   * @param {string} output - Command output
   */
  _parseAvahiOutput(output) {
    const lines = output.split('\n');

    for (const line of lines) {
      if (!line.trim() || line.startsWith('+')) continue;

      // Parseable format: =;interface;protocol;name;type;domain;hostname;address;port;txt
      const parts = line.split(';');
      
      if (parts.length >= 9 && parts[0] === '=') {
        const [, iface, protocol, name, type, domain, hostname, address, port] = parts;
        
        // Determine if IPv4 or IPv6
        const serviceInfo = {
          hostname: hostname,
          port: parseInt(port),
          serviceType: type,
          interface: iface,
        };

        if (isValidIP(address)) {
          serviceInfo.ipv4 = address;
        } else if (isValidIPv6(address)) {
          serviceInfo.ipv6 = [{
            address: address,
            type: getIPv6Type(address),
          }];
        }

        this._addServiceToMap(name, type, hostname, parseInt(port), serviceInfo);
      }
    }
  }

  /**
   * Add a discovered service to the map
   * @param {string} name - Instance name
   * @param {string} serviceType - Service type
   * @param {string} hostname - Hostname
   * @param {number} port - Port number
   * @param {Object} extra - Additional info
   */
  _addServiceToMap(name, serviceType, hostname, port, extra) {
    const key = hostname || name;
    const existing = this.discoveredServices.get(key) || {
      name,
      hostname,
      services: [],
    };

    // Add service
    existing.services = existing.services || [];
    const serviceExists = existing.services.some(
      s => s.type === serviceType && s.port === port
    );
    if (!serviceExists) {
      existing.services.push({
        type: serviceType,
        port,
        name,
      });
    }

    // Merge extra info
    if (extra.ipv4) existing.ipv4 = extra.ipv4;
    if (extra.ipv6) {
      existing.ipv6 = existing.ipv6 || [];
      for (const v6 of extra.ipv6) {
        if (!existing.ipv6.some(e => e.address === v6.address)) {
          existing.ipv6.push(v6);
        }
      }
    }

    this.discoveredServices.set(key, existing);
  }

  /**
   * Convert discovered services to device objects
   */
  _processDiscoveredServices() {
    for (const [key, service] of this.discoveredServices) {
      const device = {
        hostname: service.hostname?.replace('.local', '') || service.name,
        lastSeen: new Date().toISOString(),
        source: 'mdns',
        discoveredVia: ['mdns'],
        services: [],
      };

      // Add IP addresses
      if (service.ipv4) {
        device.ip = service.ipv4;
        device.ipv4 = service.ipv4;
      }

      if (service.ipv6?.length > 0) {
        device.ipv6 = service.ipv6;
      }

      // Convert mDNS services to port/service format
      if (service.services) {
        for (const svc of service.services) {
          if (svc.port) {
            device.services.push({
              port: svc.port,
              protocol: 'tcp',
              service: this._getServiceName(svc.type),
              version: svc.type,
            });
          }
        }

        // Extract unique ports
        device.ports = [...new Set(device.services.map(s => s.port))];
      }

      // Infer device type from services
      device.usage = this._inferUsageFromServices(service.services || []);

      // Only add if we have an IP
      if (device.ip || device.ipv6?.length > 0) {
        this._addDevice(device);
      }
    }
  }

  /**
   * Get human-readable service name from mDNS type
   * @param {string} type - mDNS service type
   * @returns {string} Service name
   */
  _getServiceName(type) {
    const serviceMap = {
      '_http._tcp': 'http',
      '_https._tcp': 'https',
      '_ssh._tcp': 'ssh',
      '_smb._tcp': 'smb',
      '_afpovertcp._tcp': 'afp',
      '_printer._tcp': 'printer',
      '_ipp._tcp': 'ipp',
      '_airplay._tcp': 'airplay',
      '_raop._tcp': 'airplay-audio',
      '_googlecast._tcp': 'chromecast',
      '_homekit._tcp': 'homekit',
      '_spotify-connect._tcp': 'spotify',
      '_daap._tcp': 'itunes',
    };
    return serviceMap[type] || type.replace(/^_|\._(tcp|udp)$/g, '');
  }

  /**
   * Infer device usage from mDNS services
   * @param {Array} services - Discovered services
   * @returns {string|null} Usage type
   */
  _inferUsageFromServices(services) {
    const types = services.map(s => s.type);

    if (types.some(t => t.includes('printer') || t.includes('ipp') || t.includes('pdl'))) {
      return 'Printer';
    }
    if (types.some(t => t.includes('airplay') || t.includes('raop') || t.includes('appletv'))) {
      return 'Media Device';
    }
    if (types.some(t => t.includes('googlecast'))) {
      return 'Media Device';
    }
    if (types.some(t => t.includes('homekit') || t.includes('hap') || t.includes('hue'))) {
      return 'IoT Device';
    }
    if (types.some(t => t.includes('sonos') || t.includes('spotify'))) {
      return 'Media Device';
    }
    if (types.some(t => t.includes('smb') || t.includes('afp'))) {
      return 'NAS/File Server';
    }
    if (types.some(t => t.includes('ssh') || t.includes('sftp'))) {
      return 'Server';
    }
    if (types.some(t => t.includes('workstation'))) {
      return 'Computer/Workstation';
    }

    return null;
  }
}

export { MDNS_SERVICE_TYPES };
