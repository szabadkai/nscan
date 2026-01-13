/**
 * Detail View Component - Expanded device detail view
 * Enhanced with dual-stack IPv4/IPv6 support
 */

import React from 'react';
import { Box, Text } from 'ink';

/**
 * Get display label for IPv6 address type
 * @param {string} type - Address type
 * @returns {string} Human-readable label
 */
const getIPv6TypeLabel = (type) => {
  const labels = {
    'link-local': 'Link-Local',
    'global': 'Global',
    'unique-local': 'ULA',
    'multicast': 'Multicast',
    'temporary': 'Temporary',
  };
  return labels[type] || type || '';
};

/**
 * Get color for IPv6 address type
 * @param {string} type - Address type
 * @returns {string} Color name
 */
const getIPv6TypeColor = (type) => {
  const colors = {
    'link-local': 'gray',
    'global': 'blue',
    'unique-local': 'cyan',
    'multicast': 'magenta',
    'temporary': 'yellow',
  };
  return colors[type] || 'white';
};

/**
 * Display detailed information about a device
 * @param {Object} props - Component props
 * @param {Object} props.device - Device object
 */
const DetailView = ({ device }) => {
  if (!device) {
    return null;
  }

  /**
   * Render IPv6 addresses section
   */
  const renderIPv6Section = () => {
    const ipv6List = device.ipv6 || [];
    if (ipv6List.length === 0) return null;

    return (
      <Box flexDirection="column" marginTop={1}>
        <Text bold>IPv6 Addresses ({ipv6List.length}):</Text>
        {ipv6List.map((v6, index) => {
          const address = typeof v6 === 'string' ? v6 : v6.address;
          const type = typeof v6 === 'object' ? v6.type : null;
          const typeLabel = getIPv6TypeLabel(type);
          const typeColor = getIPv6TypeColor(type);

          return (
            <Box key={index}>
              <Text dimColor>  • </Text>
              <Text color={typeColor}>{address}</Text>
              {typeLabel && (
                <Text dimColor> [{typeLabel}]</Text>
              )}
            </Box>
          );
        })}
      </Box>
    );
  };

  /**
   * Render discovery sources
   */
  const renderDiscoverySources = () => {
    const discoveredVia = device.discoveredVia || [];
    if (discoveredVia.length === 0) return null;

    const sourceLabels = {
      'arp': 'ARP',
      'ndp': 'NDP (IPv6)',
      'mdns': 'mDNS/Bonjour',
      'ssdp': 'SSDP/UPnP',
      'nmap': 'Nmap',
      'tcpdump': 'Passive Traffic',
      'dhcp': 'DHCP Snooping',
    };

    return (
      <Box>
        <Text bold>Discovered Via: </Text>
        <Text color="cyan">
          {discoveredVia.map(s => sourceLabels[s] || s).join(', ')}
        </Text>
      </Box>
    );
  };

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
        {device.ipv6?.length > 0 && (
          <Text dimColor> (Dual-Stack)</Text>
        )}
      </Box>

      <Box flexDirection="column">
        {/* Network Addresses */}
        <Box>
          <Text bold>IPv4 Address: </Text>
          <Text color="cyan">{device.ipv4 || device.ip || 'N/A'}</Text>
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

        {device.fqdn && device.fqdn !== device.hostname && (
          <Box>
            <Text bold>FQDN: </Text>
            <Text dimColor>{device.fqdn}</Text>
          </Box>
        )}

        {device.workgroup && (
          <Box>
            <Text bold>Workgroup: </Text>
            <Text>{device.workgroup}</Text>
          </Box>
        )}

        {/* IPv6 Addresses */}
        {renderIPv6Section()}

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

          {device.firstSeen && (
            <Box>
              <Text bold>First Seen: </Text>
              <Text dimColor>{new Date(device.firstSeen).toLocaleString()}</Text>
            </Box>
          )}

          {device.lastSeen && (
            <Box>
              <Text bold>Last Seen: </Text>
              <Text dimColor>{new Date(device.lastSeen).toLocaleString()}</Text>
            </Box>
          )}

          {renderDiscoverySources()}

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
