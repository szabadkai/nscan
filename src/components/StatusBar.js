/**
 * Status Bar Component - Bottom status bar with controls and tips
 */

import React from 'react';
import { Box, Text } from 'ink';

/**
 * Display status bar with keyboard shortcuts and status
 * @param {Object} props - Component props
 * @param {string} props.status - Current status message
 * @param {boolean} props.scanning - Whether scan is active
 * @param {number} props.deviceCount - Number of devices
 */
const StatusBar = ({ status = 'Ready', scanning = false, deviceCount = 0 }) => {
  return (
    <Box
      flexDirection="column"
      borderStyle="single"
      borderColor="gray"
      paddingX={2}
      marginTop={1}
    >
      <Box justifyContent="space-between">
        <Box>
          <Text dimColor>Status: </Text>
          <Text color={scanning ? 'yellow' : 'green'}>{status}</Text>
        </Box>
        <Box>
          <Text dimColor>Devices: </Text>
          <Text bold>{deviceCount}</Text>
        </Box>
      </Box>

      <Box marginTop={1}>
        <Text dimColor>
          Controls: <Text color="cyan">Q</Text> Quit
          {scanning && (
            <>
              {' │ '}
              <Text color="cyan">Ctrl+C</Text> Stop
            </>
          )}
          {!scanning && (
            <>
              {' │ '}
              <Text color="cyan">R</Text> Rescan
              {deviceCount > 0 && (
                <>
                  {' │ '}
                  <Text color="cyan">E</Text> Export to JSON
                </>
              )}
            </>
          )}
        </Text>
      </Box>
    </Box>
  );
};

export default StatusBar;
