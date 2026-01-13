/**
 * SSDP Scanner - Simple Service Discovery Protocol (UPnP) scanner
 * Discovers devices via SSDP multicast (smart TVs, gaming consoles, media devices, routers)
 */

import BaseScanner from './BaseScanner.js';
import dgram from 'dgram';
import { isValidIP, isValidIPv6, getIPv6Type } from '../utils/NetworkUtils.js';

/**
 * SSDP Multicast addresses and port
 */
const SSDP_IPV4_ADDRESS = '239.255.255.250';
const SSDP_IPV6_ADDRESS = 'ff02::c'; // Site-local all SSDP nodes
const SSDP_PORT = 1900;

/**
 * SSDP M-SEARCH request template
 */
const MSEARCH_REQUEST = 
  'M-SEARCH * HTTP/1.1\r\n' +
  `HOST: ${SSDP_IPV4_ADDRESS}:${SSDP_PORT}\r\n` +
  'MAN: "ssdp:discover"\r\n' +
  'MX: 3\r\n' +
  'ST: ssdp:all\r\n' +
  'USER-AGENT: nscan/1.0\r\n' +
  '\r\n';

/**
 * SSDP device types for classification
 */
const DEVICE_TYPE_MAP = {
  'urn:schemas-upnp-org:device:InternetGatewayDevice': 'Router/Gateway',
  'urn:schemas-upnp-org:device:WANDevice': 'Router/Gateway',
  'urn:schemas-upnp-org:device:WANConnectionDevice': 'Router/Gateway',
  'urn:schemas-upnp-org:device:MediaServer': 'Media Server',
  'urn:schemas-upnp-org:device:MediaRenderer': 'Media Device',
  'urn:schemas-upnp-org:device:Basic': 'Smart Device',
  'urn:schemas-upnp-org:device:Printer': 'Printer',
  'urn:schemas-upnp-org:device:Scanner': 'Scanner',
  'urn:dial-multiscreen-org:service:dial': 'Smart TV',
  'roku:ecp': 'Media Device',
  'urn:schemas-sony-com:service:ScalarWebAPI': 'Smart TV',
  'urn:schemas-sony-com:service:IRCC': 'Smart TV',
  'urn:samsung.com:device:RemoteControlReceiver': 'Smart TV',
  'urn:schemas-upnp-org:service:ContentDirectory': 'Media Server',
  'urn:schemas-upnp-org:service:AVTransport': 'Media Device',
  'urn:schemas-upnp-org:service:RenderingControl': 'Media Device',
  'xbox': 'Gaming Console',
  'playstation': 'Gaming Console',
};

/**
 * SSDP Scanner for UPnP device discovery
 */
export default class SsdpScanner extends BaseScanner {
  constructor(options = {}) {
    super('SsdpScanner', options);
    this.socket4 = null;
    this.socket6 = null;
    this.discoveredDevices = new Map();
    this.scanTimeout = options.timeout || 5000;
  }

  /**
   * Start SSDP discovery
   * @param {Object} config - Scan configuration
   * @param {number} config.timeout - Discovery timeout in ms
   * @param {boolean} config.ipv6 - Include IPv6 discovery
   */
  async start(config = {}) {
    this._onStart();

    const timeout = config.timeout || this.scanTimeout;
    const includeIPv6 = config.ipv6 !== false;

    try {
      await Promise.all([
        this._discoverIPv4(timeout),
        includeIPv6 ? this._discoverIPv6(timeout) : Promise.resolve(),
      ]);

      // Convert discovered devices to device objects
      this._processDiscoveredDevices();

      this._onComplete();
    } catch (error) {
      this._onError(error);
      throw error;
    }
  }

  /**
   * Stop SSDP discovery
   */
  async stop() {
    if (this.socket4) {
      try { this.socket4.close(); } catch {}
      this.socket4 = null;
    }
    if (this.socket6) {
      try { this.socket6.close(); } catch {}
      this.socket6 = null;
    }

    if (this.running) {
      this.running = false;
    }
  }

  /**
   * Discover devices via IPv4 SSDP
   * @param {number} timeout - Timeout in ms
   */
  async _discoverIPv4(timeout) {
    return new Promise((resolve) => {
      try {
        this.socket4 = dgram.createSocket({ type: 'udp4', reuseAddr: true });

        this.socket4.on('error', (err) => {
          console.warn('SSDP IPv4 socket error:', err.message);
          this.socket4?.close();
          resolve();
        });

        this.socket4.on('message', (msg, rinfo) => {
          this._parseResponse(msg.toString(), rinfo.address, 'ipv4');
        });

        this.socket4.bind(() => {
          try {
            // Set multicast TTL
            this.socket4.setMulticastTTL(4);
            
            // Send M-SEARCH request
            const message = Buffer.from(MSEARCH_REQUEST);
            this.socket4.send(message, 0, message.length, SSDP_PORT, SSDP_IPV4_ADDRESS);

            // Send again after a short delay for better coverage
            setTimeout(() => {
              try {
                this.socket4?.send(message, 0, message.length, SSDP_PORT, SSDP_IPV4_ADDRESS);
              } catch {}
            }, 500);
          } catch (err) {
            console.warn('SSDP send error:', err.message);
          }
        });

        // Cleanup after timeout
        setTimeout(() => {
          try {
            this.socket4?.close();
          } catch {}
          this.socket4 = null;
          resolve();
        }, timeout);
      } catch (err) {
        console.warn('SSDP IPv4 discovery failed:', err.message);
        resolve();
      }
    });
  }

  /**
   * Discover devices via IPv6 SSDP
   * @param {number} timeout - Timeout in ms
   */
  async _discoverIPv6(timeout) {
    return new Promise((resolve) => {
      try {
        this.socket6 = dgram.createSocket({ type: 'udp6', reuseAddr: true });

        this.socket6.on('error', (err) => {
          // IPv6 SSDP often fails, just log and continue
          console.warn('SSDP IPv6 socket error:', err.message);
          resolve();
        });

        this.socket6.on('message', (msg, rinfo) => {
          this._parseResponse(msg.toString(), rinfo.address, 'ipv6');
        });

        this.socket6.bind(() => {
          try {
            const message = Buffer.from(
              MSEARCH_REQUEST.replace(
                `HOST: ${SSDP_IPV4_ADDRESS}:${SSDP_PORT}`,
                `HOST: [${SSDP_IPV6_ADDRESS}]:${SSDP_PORT}`
              )
            );
            this.socket6.send(message, 0, message.length, SSDP_PORT, SSDP_IPV6_ADDRESS);
          } catch {}
        });

        setTimeout(() => {
          try {
            this.socket6?.close();
          } catch {}
          this.socket6 = null;
          resolve();
        }, timeout);
      } catch (err) {
        resolve();
      }
    });
  }

  /**
   * Parse SSDP response
   * @param {string} response - SSDP response text
   * @param {string} address - Source IP address
   * @param {string} family - Address family ('ipv4' or 'ipv6')
   */
  _parseResponse(response, address, family) {
    try {
      const headers = this._parseHeaders(response);
      
      if (!headers) return;

      // Use USN or Location as unique identifier
      const usn = headers['usn'] || headers['location'] || address;
      
      // Get or create device entry
      const existing = this.discoveredDevices.get(address) || {
        services: [],
        headers: {},
      };

      // Store address by family
      if (family === 'ipv4' && isValidIP(address)) {
        existing.ipv4 = address;
      } else if (family === 'ipv6' && isValidIPv6(address)) {
        existing.ipv6 = existing.ipv6 || [];
        if (!existing.ipv6.some(v6 => v6.address === address)) {
          existing.ipv6.push({
            address,
            type: getIPv6Type(address),
          });
        }
      }

      // Parse Location header for more info
      if (headers['location']) {
        const locationUrl = new URL(headers['location']);
        existing.locationHost = locationUrl.hostname;
        existing.locationPort = parseInt(locationUrl.port) || 80;
        
        // Sometimes location host is more reliable
        if (isValidIP(locationUrl.hostname)) {
          existing.ipv4 = locationUrl.hostname;
        }
      }

      // Store service type
      const st = headers['st'] || headers['nt'];
      if (st && !existing.services.includes(st)) {
        existing.services.push(st);
      }

      // Store relevant headers
      if (headers['server']) existing.server = headers['server'];
      if (headers['usn']) existing.usn = headers['usn'];
      if (headers['location']) existing.location = headers['location'];

      this.discoveredDevices.set(address, existing);
    } catch (error) {
      // Ignore parse errors
    }
  }

  /**
   * Parse HTTP-style headers from SSDP response
   * @param {string} response - Raw response
   * @returns {Object|null} Parsed headers
   */
  _parseHeaders(response) {
    const headers = {};
    const lines = response.split('\r\n');

    // Check if this is an M-SEARCH response
    if (!lines[0].includes('HTTP/') && !lines[0].includes('NOTIFY')) {
      return null;
    }

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      const colonIndex = line.indexOf(':');
      if (colonIndex > 0) {
        const key = line.substring(0, colonIndex).toLowerCase().trim();
        const value = line.substring(colonIndex + 1).trim();
        headers[key] = value;
      }
    }

    return Object.keys(headers).length > 0 ? headers : null;
  }

  /**
   * Convert discovered SSDP devices to device objects
   */
  _processDiscoveredDevices() {
    for (const [address, deviceInfo] of this.discoveredDevices) {
      const device = {
        lastSeen: new Date().toISOString(),
        source: 'ssdp',
        discoveredVia: ['ssdp'],
        services: [],
        ports: [],
      };

      // Set addresses
      if (deviceInfo.ipv4) {
        device.ip = deviceInfo.ipv4;
        device.ipv4 = deviceInfo.ipv4;
      }
      if (deviceInfo.ipv6?.length > 0) {
        device.ipv6 = deviceInfo.ipv6;
      }

      // Add location port as discovered port
      if (deviceInfo.locationPort) {
        device.ports.push(deviceInfo.locationPort);
        device.services.push({
          port: deviceInfo.locationPort,
          protocol: 'tcp',
          service: 'upnp',
          version: deviceInfo.server || 'UPnP',
        });
      }

      // Always add SSDP port
      if (!device.ports.includes(SSDP_PORT)) {
        device.ports.push(SSDP_PORT);
      }

      // Parse server header for OS/device info
      if (deviceInfo.server) {
        const osInfo = this._parseServerHeader(deviceInfo.server);
        if (osInfo.os) device.os = osInfo.os;
        if (osInfo.model) device.model = osInfo.model;
      }

      // Determine device type from services
      device.usage = this._inferUsageFromServices(deviceInfo.services);

      // Extract model from USN if available
      if (deviceInfo.usn && !device.model) {
        const usnMatch = deviceInfo.usn.match(/uuid:([^:]+)/);
        if (usnMatch) {
          // Clean up UUID to possible model name
          const uuid = usnMatch[1];
          if (!uuid.match(/^[0-9a-f-]+$/i)) {
            device.model = uuid;
          }
        }
      }

      // Only add if we have an IP
      if (device.ip || device.ipv6?.length > 0) {
        this._addDevice(device);
      }
    }
  }

  /**
   * Parse Server header for OS and device info
   * @param {string} server - Server header value
   * @returns {Object} Parsed info
   */
  _parseServerHeader(server) {
    const result = {};
    const lower = server.toLowerCase();

    // Detect OS
    if (lower.includes('windows')) {
      result.os = 'Windows';
      const versionMatch = server.match(/Windows[\s\/]*([\d.]+)/i);
      if (versionMatch) result.osVersion = versionMatch[1];
    } else if (lower.includes('linux')) {
      result.os = 'Linux';
    } else if (lower.includes('darwin') || lower.includes('macos')) {
      result.os = 'macOS';
    }

    // Detect device type/model
    if (lower.includes('roku')) {
      result.model = 'Roku';
    } else if (lower.includes('samsung')) {
      result.model = 'Samsung Smart TV';
    } else if (lower.includes('lg')) {
      result.model = 'LG Smart TV';
    } else if (lower.includes('sony')) {
      result.model = 'Sony Device';
    } else if (lower.includes('xbox')) {
      result.model = 'Xbox';
    } else if (lower.includes('playstation') || lower.includes('ps4') || lower.includes('ps5')) {
      result.model = 'PlayStation';
    } else if (lower.includes('chromecast')) {
      result.model = 'Chromecast';
    } else if (lower.includes('fire') && lower.includes('amazon')) {
      result.model = 'Amazon Fire';
    }

    // Extract UPnP version
    const upnpMatch = server.match(/UPnP\/([\d.]+)/i);
    if (upnpMatch) {
      result.upnpVersion = upnpMatch[1];
    }

    return result;
  }

  /**
   * Infer device usage from SSDP service types
   * @param {Array<string>} services - Service types
   * @returns {string|null} Usage type
   */
  _inferUsageFromServices(services) {
    for (const service of services) {
      const lower = service.toLowerCase();
      
      // Check direct mappings
      for (const [pattern, usage] of Object.entries(DEVICE_TYPE_MAP)) {
        if (lower.includes(pattern.toLowerCase())) {
          return usage;
        }
      }

      // Additional heuristics
      if (lower.includes('internetgateway') || lower.includes('wandevice')) {
        return 'Router/Gateway';
      }
      if (lower.includes('mediaserver') || lower.includes('contentdirectory')) {
        return 'Media Server';
      }
      if (lower.includes('mediarenderer') || lower.includes('avtransport')) {
        return 'Media Device';
      }
      if (lower.includes('printer')) {
        return 'Printer';
      }
      if (lower.includes('dial') || lower.includes('dial-multiscreen')) {
        return 'Smart TV';
      }
    }

    // Check if any service suggests a smart device
    if (services.length > 0) {
      return 'Smart Device';
    }

    return null;
  }
}
