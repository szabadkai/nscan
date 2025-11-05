/**
 * Header Component - Animated gradient header with branding
 */

import React from 'react';
import { Box, Text } from 'ink';
import BigText from 'ink-big-text';
import Gradient from 'ink-gradient';
import chalk from 'chalk';

/**
 * Application header with animated gradient title
 * @param {Object} props - Component props
 * @param {string} props.version - Application version
 */
const Header = ({ version = '1.0.0' }) => {
  return (
    <Box flexDirection="column" marginBottom={1}>
      <Gradient name="rainbow">
        <BigText text="NSCAN" font="tiny" />
      </Gradient>
      <Box marginTop={-1}>
        <Text dimColor>Network Scanner - Discover devices on your network</Text>
      </Box>
      <Box>
        <Text dimColor>Version {version}</Text>
      </Box>
    </Box>
  );
};

export default Header;
