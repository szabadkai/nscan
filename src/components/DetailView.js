/**
 * Detail View Component - Expanded device detail view
 */

import React from 'react';
import { Box, Text } from 'ink';

/**
 * Display detailed information about a device
 * @param {Object} props - Component props
 * @param {Object} props.device - Device object
 */
const DetailView = ({ device }) => {
  if (!device) {
    return null;
  }

  return (
    <Box
      flexDirection="column"
      borderStyle="double"
      borderColor="cyan"
      paddingX={2}
      paddingY={1}
      marginTop={1}
    >
      <Box marginBottom={1}>
        <Text bold color="cyan">
          Device Details
        </Text>
      </Box>

      <Box flexDirection="column">
        {/* Basic Info */}
        <Box>
          <Text bold>IP Address: </Text>
          <Text color="cyan">{device.ip || 'N/A'}</Text>
        </Box>

        <Box>
          <Text bold>MAC Address: </Text>
          <Text color="gray">{device.mac || 'N/A'}</Text>
        </Box>

        {device.hostname && (
          <Box>
            <Text bold>Hostname: </Text>
            <Text>{device.hostname}</Text>
          </Box>
        )}

        {/* Device Info */}
        {device.manufacturer && (
          <Box marginTop={1}>
            <Text bold>Manufacturer: </Text>
            <Text color="green">{device.manufacturer}</Text>
          </Box>
        )}

        {device.model && (
          <Box>
            <Text bold>Model: </Text>
            <Text>{device.model}</Text>
          </Box>
        )}

        {device.usage && (
          <Box>
            <Text bold>Usage Type: </Text>
            <Text color="magenta">{device.usage}</Text>
          </Box>
        )}

        {/* OS Info */}
        {device.os && (
          <Box marginTop={1}>
            <Text bold>Operating System: </Text>
            <Text color="blue">{device.os}</Text>
            {device.osVersion && <Text dimColor> ({device.osVersion})</Text>}
          </Box>
        )}

        {/* Network Info */}
        {device.ports && device.ports.length > 0 && (
          <Box marginTop={1} flexDirection="column">
            <Text bold>Open Ports ({device.ports.length}):</Text>
            <Box flexWrap="wrap">
              <Text color="yellow">{device.ports.join(', ')}</Text>
            </Box>
          </Box>
        )}

        {device.services && device.services.length > 0 && (
          <Box marginTop={1} flexDirection="column">
            <Text bold>Services:</Text>
            {device.services.slice(0, 5).map((service, index) => (
              <Box key={index}>
                <Text dimColor>  • </Text>
                <Text>
                  {service.port}/{service.protocol} - {service.service}
                </Text>
                {service.version && <Text dimColor> ({service.version})</Text>}
              </Box>
            ))}
            {device.services.length > 5 && (
              <Text dimColor>  ... and {device.services.length - 5} more</Text>
            )}
          </Box>
        )}

        {/* Meta Info */}
        <Box marginTop={1} flexDirection="column">
          <Box>
            <Text bold>Confidence: </Text>
            <Text color={device.confidence > 70 ? 'green' : device.confidence > 40 ? 'yellow' : 'red'}>
              {device.confidence}%
            </Text>
          </Box>

          {device.lastSeen && (
            <Box>
              <Text bold>Last Seen: </Text>
              <Text dimColor>{new Date(device.lastSeen).toLocaleString()}</Text>
            </Box>
          )}

          {device.sources && device.sources.length > 0 && (
            <Box>
              <Text bold>Data Sources: </Text>
              <Text dimColor>{device.sources.join(', ')}</Text>
            </Box>
          )}
        </Box>
      </Box>
    </Box>
  );
};

export default DetailView;
