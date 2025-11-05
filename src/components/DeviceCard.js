/**
 * Device Card Component - Display individual device with animations
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
 */
const DeviceCard = ({ device, analyzing = false, selected = false }) => {
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

  // Format IP with fixed width
  const ipDisplay = (device.ip || 'N/A').padEnd(15);

  // Build info string
  const parts = [];
  if (device.hostname) parts.push(truncate(device.hostname, 20));
  if (device.manufacturer) parts.push(truncate(device.manufacturer, 15));
  if (device.usage) parts.push(device.usage);
  if (device.os) parts.push(device.os);

  const infoDisplay = parts.join(' · ');

  return (
    <Box>
      {getStatusIcon()}
      <Text> </Text>
      <Text color="cyan">{ipDisplay}</Text>
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
