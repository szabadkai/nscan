/**
 * Output formatting utilities for JSON, CSV, and table formats
 */

/**
 * Format devices as JSON
 * @param {Array<Object>} devices - Array of device objects
 * @param {Object} metadata - Scan metadata
 * @returns {string} JSON string
 */
export function formatJSON(devices, metadata = {}) {
  const output = {
    metadata: {
      timestamp: new Date().toISOString(),
      deviceCount: devices.length,
      ...metadata,
    },
    devices: devices.map((device) => ({
      ip: device.ip,
      mac: device.mac,
      hostname: device.hostname || 'Unknown',
      manufacturer: device.manufacturer || 'Unknown',
      os: device.os || 'Unknown',
      osVersion: device.osVersion || '',
      model: device.model || '',
      usage: device.usage || 'Unknown',
      ports: device.ports || [],
      services: device.services || [],
      sources: device.sources || [],
      firstSeen: device.firstSeen,
      lastSeen: device.lastSeen,
      confidence: device.confidence || 0,
    })),
  };

  return JSON.stringify(output, null, 2);
}

/**
 * Format devices as CSV
 * @param {Array<Object>} devices - Array of device objects
 * @returns {string} CSV string
 */
export function formatCSV(devices) {
  const headers = [
    'IP',
    'MAC',
    'Hostname',
    'Manufacturer',
    'OS',
    'OS Version',
    'Model',
    'Usage',
    'Open Ports',
    'Confidence',
    'Sources',
    'First Seen',
    'Last Seen',
  ];

  const rows = devices.map((device) => [
    device.ip || '',
    device.mac || '',
    escapeCsvField(device.hostname || 'Unknown'),
    escapeCsvField(device.manufacturer || 'Unknown'),
    escapeCsvField(device.os || 'Unknown'),
    escapeCsvField(device.osVersion || ''),
    escapeCsvField(device.model || ''),
    escapeCsvField(device.usage || 'Unknown'),
    device.ports ? device.ports.join(';') : '',
    device.confidence || 0,
    device.sources ? device.sources.join(';') : '',
    device.firstSeen || '',
    device.lastSeen || '',
  ]);

  const csvLines = [headers.join(','), ...rows.map((row) => row.join(','))];

  return csvLines.join('\n');
}

/**
 * Escape CSV field if it contains special characters
 * @param {string} field - Field value
 * @returns {string} Escaped field
 */
function escapeCsvField(field) {
  if (!field) return '';

  const fieldStr = String(field);

  // If field contains comma, quote, or newline, wrap in quotes and escape quotes
  if (fieldStr.includes(',') || fieldStr.includes('"') || fieldStr.includes('\n')) {
    return `"${fieldStr.replace(/"/g, '""')}"`;
  }

  return fieldStr;
}

/**
 * Format devices as ASCII table
 * @param {Array<Object>} devices - Array of device objects
 * @returns {string} ASCII table string
 */
export function formatTable(devices) {
  if (devices.length === 0) {
    return 'No devices found.';
  }

  const headers = ['IP', 'MAC', 'Hostname', 'Manufacturer', 'OS', 'Usage'];

  const rows = devices.map((device) => [
    device.ip || '',
    device.mac || '',
    truncate(device.hostname || 'Unknown', 20),
    truncate(device.manufacturer || 'Unknown', 20),
    truncate(device.os || 'Unknown', 15),
    truncate(device.usage || 'Unknown', 15),
  ]);

  // Calculate column widths
  const columnWidths = headers.map((header, i) => {
    const headerWidth = header.length;
    const maxDataWidth = Math.max(...rows.map((row) => String(row[i]).length));
    return Math.max(headerWidth, maxDataWidth);
  });

  // Create separator line
  const separator = '+' + columnWidths.map((w) => '-'.repeat(w + 2)).join('+') + '+';

  // Format header
  const headerRow =
    '|' +
    headers
      .map((header, i) => ' ' + header.padEnd(columnWidths[i]) + ' ')
      .join('|') +
    '|';

  // Format data rows
  const dataRows = rows.map(
    (row) =>
      '|' +
      row.map((cell, i) => ' ' + String(cell).padEnd(columnWidths[i]) + ' ').join('|') +
      '|'
  );

  // Combine everything
  return [separator, headerRow, separator, ...dataRows, separator].join('\n');
}

/**
 * Truncate string to specified length
 * @param {string} str - String to truncate
 * @param {number} length - Max length
 * @returns {string} Truncated string
 */
function truncate(str, length) {
  if (!str) return '';
  const s = String(str);
  return s.length > length ? s.substring(0, length - 3) + '...' : s;
}

/**
 * Format a summary of scan results
 * @param {Array<Object>} devices - Array of device objects
 * @param {Object} stats - Scan statistics
 * @returns {string} Summary string
 */
export function formatSummary(devices, stats = {}) {
  const lines = [
    '═════════════════════════════════════════',
    '           SCAN SUMMARY',
    '═════════════════════════════════════════',
    '',
    `Total Devices Found: ${devices.length}`,
    `Scan Duration: ${stats.duration || 'N/A'}`,
    `Network Range: ${stats.range || 'N/A'}`,
    '',
  ];

  // Count by device type
  const usageTypes = {};
  devices.forEach((device) => {
    const usage = device.usage || 'Unknown';
    usageTypes[usage] = (usageTypes[usage] || 0) + 1;
  });

  if (Object.keys(usageTypes).length > 0) {
    lines.push('Device Types:');
    Object.entries(usageTypes)
      .sort((a, b) => b[1] - a[1])
      .forEach(([type, count]) => {
        lines.push(`  ${type}: ${count}`);
      });
    lines.push('');
  }

  // Count by manufacturer
  const manufacturers = {};
  devices.forEach((device) => {
    const mfr = device.manufacturer || 'Unknown';
    manufacturers[mfr] = (manufacturers[mfr] || 0) + 1;
  });

  if (Object.keys(manufacturers).length > 0) {
    lines.push('Top Manufacturers:');
    Object.entries(manufacturers)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .forEach(([mfr, count]) => {
        lines.push(`  ${mfr}: ${count}`);
      });
  }

  lines.push('═════════════════════════════════════════');

  return lines.join('\n');
}
