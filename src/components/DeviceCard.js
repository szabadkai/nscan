/**
 * Device Card Component - Display individual device with animations
 * Enhanced with dual-stack IPv4/IPv6 support
 */

import React from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import chalk from 'chalk';

/**
 * Display a single device with all its information
 * @param {Object} props - Component props
 * @param {Object} props.device - Device object
 * @param {boolean} props.analyzing - Whether device is being analyzed
 * @param {boolean} props.selected - Whether device is selected
 * @param {boolean} props.showIPv6 - Whether to show IPv6 addresses
 */
const DeviceCard = ({ device, analyzing = false, selected = false, showIPv6 = true }) => {
  /**
   * Get status icon for device
   */
  const getStatusIcon = () => {
    if (analyzing) {
      return <Text color="yellow">⋯</Text>;
    }
    if (device.confidence > 70) {
      return <Text color="green">✓</Text>;
    }
    if (device.confidence > 40) {
      return <Text color="yellow">⚠</Text>;
    }
    return <Text dimColor>·</Text>;
  };

  /**
   * Get usage color
   */
  const getUsageColor = (usage) => {
    const colorMap = {
      'Router/Gateway': 'magenta',
      Server: 'blue',
      'Computer/Workstation': 'cyan',
      'Mobile Device': 'green',
      'IoT Device': 'yellow',
      Printer: 'gray',
      Unknown: 'dim',
    };

    return colorMap[usage] || 'white';
  };

  /**
   * Truncate string to max length
   */
  const truncate = (str, maxLen) => {
    if (!str) return '';
    return str.length > maxLen ? str.substring(0, maxLen - 1) + '…' : str;
  };

  /**
   * Get primary IP address for display (prefer IPv4)
   */
  const getPrimaryIP = () => {
    return device.ipv4 || device.ip || 'N/A';
  };

  /**
   * Get IPv6 summary indicator
   */
  const getIPv6Indicator = () => {
    const ipv6List = device.ipv6 || [];
    if (!ipv6List.length || !showIPv6) return null;

    // Count address types
    const hasGlobal = ipv6List.some(v6 => 
      (typeof v6 === 'object' ? v6.type : null) === 'global' ||
      (typeof v6 === 'string' && !v6.startsWith('fe80:'))
    );
    const linkLocalOnly = ipv6List.every(v6 =>
      (typeof v6 === 'object' ? v6.type : null) === 'link-local' ||
      (typeof v6 === 'string' && v6.startsWith('fe80:'))
    );

    if (hasGlobal) {
      return <Text color="blue">⁶</Text>; // Has global IPv6
    }
    if (linkLocalOnly) {
      return <Text dimColor>⁶</Text>; // Only link-local
    }
    return <Text color="gray">⁶</Text>;
  };

  // Format IP with fixed width
  const ipDisplay = getPrimaryIP().padEnd(15);

  // Hostname display - make it prominent
  const hostnameDisplay = device.hostname ? truncate(device.hostname, 25) : null;

  // Build secondary info string (everything except hostname)
  const parts = [];
  if (device.manufacturer) parts.push(truncate(device.manufacturer, 15));
  if (device.usage) parts.push(device.usage);
  if (device.os) parts.push(device.os);

  const infoDisplay = parts.join(' · ');

  // Discovery source indicator
  const getSourceIndicator = () => {
    const sources = device.discoveredVia || device.sources || [];
    const indicators = [];
    
    if (sources.includes('mdns') || sources.includes('mDNS')) {
      indicators.push(<Text key="m" color="green">m</Text>);
    }
    if (sources.includes('ssdp') || sources.includes('SSDP')) {
      indicators.push(<Text key="s" color="yellow">s</Text>);
    }
    if (sources.includes('ndp') || sources.includes('NDP')) {
      indicators.push(<Text key="n" color="blue">n</Text>);
    }
    
    return indicators.length > 0 ? (
      <Text dimColor>[</Text>
    ) : null;
  };

  return (
    <Box>
      {getStatusIcon()}
      <Text> </Text>
      {hostnameDisplay ? (
        <>
          <Text bold color="white">{hostnameDisplay.padEnd(25)}</Text>
          <Text dimColor> </Text>
          <Text color="yellow">{ipDisplay}</Text>
        </>
      ) : (
        <>
          <Text dimColor>{"(unknown)".padEnd(25)}</Text>
          <Text dimColor> </Text>
          <Text color="cyan">{ipDisplay}</Text>
        </>
      )}
      {getIPv6Indicator()}
      <Text dimColor> </Text>
      <Text color="gray">{truncate(device.mac || '', 17)}</Text>
      {infoDisplay && (
        <>
          <Text dimColor> │ </Text>
          <Text>{infoDisplay}</Text>
        </>
      )}
      {selected && <Text color="yellow"> ◀</Text>}
    </Box>
  );
};

export default DeviceCard;
