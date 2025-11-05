/**
 * Loading Spinner Component - Animated spinner for loading states
 */

import React from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import chalk from 'chalk';

/**
 * Loading spinner with customizable message and color
 * @param {Object} props - Component props
 * @param {string} props.message - Loading message
 * @param {string} props.type - Spinner type (dots, line, etc.)
 * @param {string} props.color - Spinner color
 */
const LoadingSpinner = ({ message = 'Loading...', type = 'dots', color = 'cyan' }) => {
  return (
    <Box>
      <Text color={color}>
        <Spinner type={type} /> {message}
      </Text>
    </Box>
  );
};

export default LoadingSpinner;
