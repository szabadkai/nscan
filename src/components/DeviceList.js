/**
 * Device List Component - Scrollable list of discovered devices
 */

import React from 'react';
import { Box, Text } from 'ink';
import DeviceCard from './DeviceCard.js';

/**
 * Display list of discovered devices
 * @param {Object} props - Component props
 * @param {Array} props.devices - Array of device objects
 * @param {number} props.selectedIndex - Index of selected device
 */
const DeviceList = ({ devices = [], selectedIndex = -1 }) => {
  if (devices.length === 0) {
    return (
      <Box flexDirection="column" paddingX={1}>
        <Text dimColor>No devices discovered yet...</Text>
      </Box>
    );
  }

  return (
    <Box flexDirection="column" paddingX={1}>
      <Box>
        <Text bold color="cyan">
          Discovered Devices ({devices.length})
        </Text>
        <Text dimColor> ─────────────────────────────────────────────────────────</Text>
      </Box>

      <Box flexDirection="column">
        {devices.map((device, index) => (
          <DeviceCard
            key={device.ip || device.mac || index}
            device={device}
            analyzing={!device.usage || !device.manufacturer}
            selected={index === selectedIndex}
          />
        ))}
      </Box>
    </Box>
  );
};

export default DeviceList;
