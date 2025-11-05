/**
 * Scan Progress Component - Live progress bar with statistics
 */

import React from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import chalk from 'chalk';

/**
 * Display scan progress with statistics
 * @param {Object} props - Component props
 * @param {boolean} props.scanning - Whether scan is active
 * @param {string} props.phase - Current scan phase
 * @param {number} props.deviceCount - Number of devices found
 * @param {number} props.duration - Scan duration in seconds
 * @param {number} props.progress - Progress percentage (0-100)
 */
const ScanProgress = ({
  scanning = false,
  phase = 'Initializing',
  deviceCount = 0,
  duration = 0,
  progress = 0,
}) => {
  /**
   * Format duration as MM:SS
   */
  const formatDuration = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  };

  /**
   * Get phase description
   */
  const getPhaseDescription = (phase) => {
    const descriptions = {
      'Initializing': 'Preparing scanner and checking system...',
      'Fast Discovery': 'Quick ARP scan for immediate device detection',
      'Deep Scan': 'Detailed nmap scan with OS and service detection',
      'Passive Monitoring': 'Analyzing network traffic passively',
    };
    return descriptions[phase] || phase;
  };

  /**
   * Render progress bar
   */
  const renderProgressBar = () => {
    const width = 40;
    const filled = Math.round((progress / 100) * width);
    const empty = width - filled;

    return (
      <Box>
        <Text color="cyan">[</Text>
        <Text color="green">{'█'.repeat(filled)}</Text>
        <Text dimColor>{'░'.repeat(empty)}</Text>
        <Text color="cyan">] {progress}%</Text>
      </Box>
    );
  };

  return (
    <Box
      flexDirection="column"
      borderStyle="round"
      borderColor="cyan"
      paddingX={2}
      paddingY={1}
      marginBottom={1}
    >
      <Box marginBottom={1}>
        <Text bold color="cyan">
          Scan Progress
        </Text>
      </Box>

      <Box flexDirection="column" marginBottom={1}>
        {scanning ? (
          <Box>
            <Text color="yellow">
              <Spinner type="dots" />
            </Text>
            <Text bold> {phase}</Text>
          </Box>
        ) : (
          <Text color="green" bold>✓ Scan Complete</Text>
        )}
        {scanning && (
          <Box marginLeft={2}>
            <Text dimColor>{getPhaseDescription(phase)}</Text>
          </Box>
        )}
      </Box>

      {scanning && progress > 0 && renderProgressBar()}

      <Box flexDirection="column" marginTop={1}>
        <Box justifyContent="space-between">
          <Box>
            <Text dimColor>Devices Found: </Text>
            <Text bold color="green">
              {deviceCount}
            </Text>
          </Box>
          <Box marginLeft={4}>
            <Text dimColor>Duration: </Text>
            <Text bold>{formatDuration(duration)}</Text>
          </Box>
        </Box>
      </Box>
    </Box>
  );
};

export default ScanProgress;
