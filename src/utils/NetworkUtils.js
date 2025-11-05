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
