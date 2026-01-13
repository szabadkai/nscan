/**
 * Error Display Component - Show errors with helpful guidance
 */

import React from 'react';
import { Box, Text } from 'ink';

/**
 * Display error with helpful suggestions
 * @param {Object} props - Component props
 * @param {string} props.error - Error message
 * @param {Array} props.missing - Missing dependencies
 */
const ErrorDisplay = ({ error, missing = [] }) => {
  return (
    <Box flexDirection="column" paddingX={2} paddingY={1}>
      <Box marginBottom={1}>
        <Text bold color="red">
          ✗ Error
        </Text>
      </Box>

      <Box marginBottom={1}>
        <Text>{error}</Text>
      </Box>

      {missing && missing.length > 0 && (
        <Box flexDirection="column" marginTop={1}>
          <Text bold color="yellow">
            Missing Dependencies:
          </Text>
          {missing.map((dep, index) => (
            <Box key={index} flexDirection="column" marginTop={1}>
              <Text color="cyan">• {dep.command}</Text>
              <Text dimColor>  Install: {dep.install}</Text>
            </Box>
          ))}
        </Box>
      )}

      {error.includes('privileges') && (
        <Box flexDirection="column" marginTop={2} borderStyle="single" borderColor="yellow" paddingX={2} paddingY={1}>
          <Text bold color="yellow">
            💡 Quick Fix:
          </Text>
          {process.platform === 'win32' ? (
            <>
              <Text color="green" marginTop={1}>
                Run as Administrator:
              </Text>
              <Text color="cyan">  1. Right-click CMD/PowerShell</Text>
              <Text color="cyan">  2. Run as administrator</Text>
              <Text color="cyan">  3. Run: nscan</Text>
            </>
          ) : (
            <>
              <Text color="green" marginTop={1}>
                Run with sudo:
              </Text>
              <Text color="cyan">  sudo nscan</Text>
            </>
          )}
        </Box>
      )}

      {error.includes('nmap') && (
        <Box flexDirection="column" marginTop={2} borderStyle="single" borderColor="yellow" paddingX={2} paddingY={1}>
          <Text bold color="yellow">
            💡 Install nmap:
          </Text>
          <Text color="cyan" marginTop={1}>
            macOS:   brew install nmap
          </Text>
          <Text color="cyan">
            Linux:   sudo apt-get install nmap
          </Text>
          <Text color="cyan">
            Windows: https://nmap.org/download.html
          </Text>
        </Box>
      )}

      <Box marginTop={2}>
        <Text dimColor>Press Q to quit</Text>
      </Box>
    </Box>
  );
};

export default ErrorDisplay;
