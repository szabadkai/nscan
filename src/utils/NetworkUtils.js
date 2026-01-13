/**
 * Network utility functions for CIDR calculations, IP validation, and network interface detection
 */

import { networkInterfaces } from 'os';

/**
 * Validate an IP address (IPv4)
 * @param {string} ip - IP address to validate
 * @returns {boolean} True if valid IPv4 address
 */
export function isValidIP(ip) {
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipv4Regex.test(ip)) {
    return false;
  }

  const parts = ip.split('.');
  return parts.every((part) => {
    const num = parseInt(part, 10);
    return num >= 0 && num <= 255;
  });
}

/**
 * Validate CIDR notation
 * @param {string} cidr - CIDR string (e.g., "192.168.1.0/24")
 * @returns {boolean} True if valid CIDR
 */
export function isValidCIDR(cidr) {
  const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/;
  if (!cidrRegex.test(cidr)) {
    return false;
  }

  const [ip, maskBits] = cidr.split('/');
  const mask = parseInt(maskBits, 10);

  return isValidIP(ip) && mask >= 0 && mask <= 32;
}

/**
 * Convert IP address to integer
 * @param {string} ip - IP address
 * @returns {number} IP as integer
 */
export function ipToInt(ip) {
  const parts = ip.split('.');
  return (
    (parseInt(parts[0]) << 24) |
    (parseInt(parts[1]) << 16) |
    (parseInt(parts[2]) << 8) |
    parseInt(parts[3])
  );
}

/**
 * Convert integer to IP address
 * @param {number} int - Integer representation of IP
 * @returns {string} IP address
 */
export function intToIp(int) {
  return [
    (int >>> 24) & 0xff,
    (int >>> 16) & 0xff,
    (int >>> 8) & 0xff,
    int & 0xff,
  ].join('.');
}

/**
 * Calculate network address from IP and mask
 * @param {string} ip - IP address
 * @param {number} maskBits - Network mask bits
 * @returns {string} Network address
 */
export function getNetworkAddress(ip, maskBits) {
  const ipInt = ipToInt(ip);
  const mask = (-1 << (32 - maskBits)) >>> 0;
  const networkInt = (ipInt & mask) >>> 0;
  return intToIp(networkInt);
}

/**
 * Calculate broadcast address from IP and mask
 * @param {string} ip - IP address
 * @param {number} maskBits - Network mask bits
 * @returns {string} Broadcast address
 */
export function getBroadcastAddress(ip, maskBits) {
  const ipInt = ipToInt(ip);
  const mask = (-1 << (32 - maskBits)) >>> 0;
  const broadcastInt = (ipInt | ~mask) >>> 0;
  return intToIp(broadcastInt);
}

/**
 * Calculate number of hosts in a network
 * @param {number} maskBits - Network mask bits
 * @returns {number} Number of usable hosts
 */
export function getHostCount(maskBits) {
  return Math.pow(2, 32 - maskBits) - 2; // Subtract network and broadcast addresses
}

/**
 * Get IP range from CIDR
 * @param {string} cidr - CIDR notation
 * @returns {Object} Range with start and end IPs
 */
export function getCIDRRange(cidr) {
  const [ip, maskBits] = cidr.split('/');
  const mask = parseInt(maskBits, 10);

  const networkAddr = getNetworkAddress(ip, mask);
  const broadcastAddr = getBroadcastAddress(ip, mask);

  return {
    network: networkAddr,
    broadcast: broadcastAddr,
    firstHost: intToIp(ipToInt(networkAddr) + 1),
    lastHost: intToIp(ipToInt(broadcastAddr) - 1),
    hostCount: getHostCount(mask),
  };
}

/**
 * Normalize MAC address to standard format
 * @param {string} mac - MAC address in any format
 * @returns {string} Normalized MAC address (XX:XX:XX:XX:XX:XX)
 */
export function normalizeMac(mac) {
  // Remove common separators
  const cleaned = mac.replace(/[:-]/g, '').toUpperCase();

  // Validate length
  if (cleaned.length !== 12) {
    return mac; // Return original if invalid
  }

  // Insert colons
  return cleaned.match(/.{2}/g).join(':');
}

/**
 * Get MAC OUI (first 3 octets) for vendor lookup
 * @param {string} mac - MAC address
 * @returns {string} OUI portion
 */
export function getMacOUI(mac) {
  const normalized = normalizeMac(mac);
  return normalized.split(':').slice(0, 3).join(':');
}

/**
 * Detect active network interfaces
 * @param {boolean} excludeInternal - Exclude loopback and internal interfaces
 * @returns {Array<Object>} Array of network interface information
 */
export function getActiveInterfaces(excludeInternal = true) {
  const interfaces = networkInterfaces();
  const active = [];

  for (const [name, addrs] of Object.entries(interfaces)) {
    if (!addrs) continue;

    for (const addr of addrs) {
      // Skip IPv6 and internal addresses if requested
      if (addr.family !== 'IPv4') continue;
      if (excludeInternal && addr.internal) continue;

      active.push({
        name,
        address: addr.address,
        netmask: addr.netmask,
        mac: addr.mac,
        cidr: addr.cidr,
      });
    }
  }

  return active;
}

/**
 * Auto-detect the primary network interface and its CIDR
 * @returns {Object|null} Primary interface info or null
 */
export function detectPrimaryInterface() {
  const interfaces = getActiveInterfaces(true);

  if (interfaces.length === 0) {
    return null;
  }

  // Prefer interfaces with common private network ranges
  const preferred = interfaces.find((iface) => {
    const ip = iface.address;
    return (
      ip.startsWith('192.168.') ||
      ip.startsWith('10.') ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)
    );
  });

  return preferred || interfaces[0];
}

/**
 * Check if IP is in a private range
 * @param {string} ip - IP address
 * @returns {boolean} True if private IP
 */
export function isPrivateIP(ip) {
  const parts = ip.split('.').map(Number);

  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168) ||
    parts[0] === 127
  );
}

/**
 * Check if interface is a VPN or tunnel
 * @param {string} name - Interface name
 * @returns {boolean} True if likely VPN/tunnel
 */
export function isVPNInterface(name) {
  const vpnPatterns = /^(tun|tap|utun|ppp|ipsec|vpn|wireguard|wg)/i;
  return vpnPatterns.test(name);
}

// ============================================================================
// IPv6 Support
// ============================================================================

/**
 * Validate an IPv6 address
 * Handles full, compressed, and zone ID formats (e.g., fe80::1%en0)
 * @param {string} ip - IPv6 address to validate
 * @returns {boolean} True if valid IPv6 address
 */
export function isValidIPv6(ip) {
  if (!ip || typeof ip !== 'string') {
    return false;
  }

  // Remove zone ID if present (e.g., fe80::1%en0 -> fe80::1)
  const addr = ip.split('%')[0];

  // Basic IPv6 regex patterns
  const fullPattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  const compressedPattern = /^(([0-9a-fA-F]{1,4}:)*)?::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
  const startCompressed = /^::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$/;
  const endCompressed = /^([0-9a-fA-F]{1,4}:)+:$/;
  const onlyCompressed = /^::$/;

  // Check for valid patterns
  if (
    fullPattern.test(addr) ||
    compressedPattern.test(addr) ||
    startCompressed.test(addr) ||
    endCompressed.test(addr) ||
    onlyCompressed.test(addr)
  ) {
    // Additional validation: ensure no more than one ::
    const doubleColonCount = (addr.match(/::/g) || []).length;
    if (doubleColonCount > 1) {
      return false;
    }

    // Ensure we have the right number of groups
    const groups = addr.replace('::', ':').split(':').filter(Boolean);
    if (doubleColonCount === 0 && groups.length !== 8) {
      return false;
    }
    if (doubleColonCount === 1 && groups.length > 7) {
      return false;
    }

    return true;
  }

  return false;
}

/**
 * Check if IPv6 address is link-local (fe80::/10)
 * @param {string} ip - IPv6 address
 * @returns {boolean} True if link-local
 */
export function isLinkLocalIPv6(ip) {
  if (!ip) return false;
  const addr = ip.split('%')[0].toLowerCase();
  return addr.startsWith('fe80:') || addr.startsWith('fe80::');
}

/**
 * Check if IPv6 address is global unicast (2000::/3)
 * @param {string} ip - IPv6 address
 * @returns {boolean} True if global unicast
 */
export function isGlobalUnicastIPv6(ip) {
  if (!ip) return false;
  const addr = ip.split('%')[0].toLowerCase();
  const firstGroup = addr.split(':')[0];
  const firstValue = parseInt(firstGroup, 16);
  // Global unicast: first 3 bits are 001 (0x2000 - 0x3fff)
  return firstValue >= 0x2000 && firstValue <= 0x3fff;
}

/**
 * Check if IPv6 address is unique local (fc00::/7)
 * Similar to RFC1918 private addresses
 * @param {string} ip - IPv6 address
 * @returns {boolean} True if unique local
 */
export function isUniqueLocalIPv6(ip) {
  if (!ip) return false;
  const addr = ip.split('%')[0].toLowerCase();
  return addr.startsWith('fc') || addr.startsWith('fd');
}

/**
 * Check if IPv6 address is multicast (ff00::/8)
 * @param {string} ip - IPv6 address
 * @returns {boolean} True if multicast
 */
export function isMulticastIPv6(ip) {
  if (!ip) return false;
  const addr = ip.split('%')[0].toLowerCase();
  return addr.startsWith('ff');
}

/**
 * Extract zone ID from IPv6 address (e.g., fe80::1%en0 -> en0)
 * @param {string} ip - IPv6 address with possible zone ID
 * @returns {string|null} Zone ID or null
 */
export function getIPv6ZoneId(ip) {
  if (!ip || typeof ip !== 'string') return null;
  const parts = ip.split('%');
  return parts.length > 1 ? parts[1] : null;
}

/**
 * Remove zone ID from IPv6 address
 * @param {string} ip - IPv6 address with possible zone ID
 * @returns {string} IPv6 address without zone ID
 */
export function stripIPv6ZoneId(ip) {
  if (!ip || typeof ip !== 'string') return ip;
  return ip.split('%')[0];
}

/**
 * Get IPv6 address type description
 * @param {string} ip - IPv6 address
 * @returns {string} Address type description
 */
export function getIPv6Type(ip) {
  if (isLinkLocalIPv6(ip)) return 'link-local';
  if (isGlobalUnicastIPv6(ip)) return 'global';
  if (isUniqueLocalIPv6(ip)) return 'unique-local';
  if (isMulticastIPv6(ip)) return 'multicast';
  if (ip && ip.toLowerCase() === '::1') return 'loopback';
  return 'unknown';
}

/**
 * Detect active network interfaces with IPv6 support
 * @param {boolean} excludeInternal - Exclude loopback and internal interfaces
 * @param {boolean} includeIPv6 - Include IPv6 addresses
 * @returns {Array<Object>} Array of network interface information
 */
export function getActiveInterfacesWithIPv6(excludeInternal = true, includeIPv6 = true) {
  const interfaces = networkInterfaces();
  const active = [];
  const ifaceMap = new Map(); // Group by interface name

  for (const [name, addrs] of Object.entries(interfaces)) {
    if (!addrs) continue;

    for (const addr of addrs) {
      if (excludeInternal && addr.internal) continue;

      // Skip if not IPv4 or IPv6
      if (addr.family !== 'IPv4' && addr.family !== 'IPv6') continue;
      if (!includeIPv6 && addr.family === 'IPv6') continue;

      // Skip multicast and loopback IPv6
      if (addr.family === 'IPv6') {
        if (isMulticastIPv6(addr.address)) continue;
        if (addr.address === '::1') continue;
      }

      // Get or create interface entry
      let iface = ifaceMap.get(name);
      if (!iface) {
        iface = {
          name,
          mac: addr.mac,
          ipv4: null,
          ipv4Cidr: null,
          ipv6: [],
        };
        ifaceMap.set(name, iface);
      }

      if (addr.family === 'IPv4') {
        iface.ipv4 = addr.address;
        iface.ipv4Cidr = addr.cidr;
        iface.netmask = addr.netmask;
      } else if (addr.family === 'IPv6') {
        iface.ipv6.push({
          address: addr.address,
          type: getIPv6Type(addr.address),
          cidr: addr.cidr,
          scopeid: addr.scopeid,
        });
      }
    }
  }

  // Convert map to array and filter out interfaces without any addresses
  for (const iface of ifaceMap.values()) {
    if (iface.ipv4 || iface.ipv6.length > 0) {
      active.push(iface);
    }
  }

  return active;
}

/**
 * Auto-detect the primary network interface with IPv6 support
 * @returns {Object|null} Primary interface info or null
 */
export function detectPrimaryInterfaceWithIPv6() {
  const interfaces = getActiveInterfacesWithIPv6(true, true);

  if (interfaces.length === 0) {
    return null;
  }

  // Prefer interfaces with common private IPv4 network ranges
  const preferred = interfaces.find((iface) => {
    const ip = iface.ipv4;
    if (!ip) return false;
    return (
      ip.startsWith('192.168.') ||
      ip.startsWith('10.') ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip)
    );
  });

  return preferred || interfaces[0];
}

/**
 * Check if an address is IPv4 or IPv6
 * @param {string} ip - IP address
 * @returns {'ipv4'|'ipv6'|null} Address family or null if invalid
 */
export function getAddressFamily(ip) {
  if (isValidIP(ip)) return 'ipv4';
  if (isValidIPv6(ip)) return 'ipv6';
  return null;
}
