/**
 * Main coordinator - Connects scanners to UI
 */

import React from 'react';
import { render } from 'ink';
import App from './components/App.js';
import ScanOrchestrator from './scanners/ScanOrchestrator.js';
import { DemoScanner } from './utils/DemoMode.js';
import { formatJSON, formatCSV, formatTable, formatSummary } from './utils/OutputFormatter.js';
import { writeFileSync } from 'fs';

/**
 * Start the network scanner
 * @param {Object} options - Scan options
 * @returns {Promise<Array>} Array of discovered devices
 */
export async function startScan(options = {}, registerCleanupFn = null) {
  const {
    range,
    interface: iface,
    passive = false,
    watch = false,
    fast = false,
    detectOS = true,
    timeout = 30,
    format = 'interactive',
    export: exportPath,
    demo = false,
  } = options;

  // Create orchestrator or demo scanner
  const orchestrator = demo
    ? new DemoScanner()
    : new ScanOrchestrator({
        passive,
        fast,
        detectOS,
        watch,
        timeout,
      });

  // Register cleanup callback if provided
  if (registerCleanupFn && typeof registerCleanupFn === 'function') {
    registerCleanupFn(async () => {
      if (orchestrator && orchestrator.isRunning()) {
        await orchestrator.stop();
      }
    });
  }

  // Build scan configuration
  const config = {
    cidr: range,
    interface: iface,
    fast,
  };

  // If format is not interactive, run headless
  if (format !== 'interactive') {
    return await runHeadless(orchestrator, config, format, exportPath);
  }

  // Run interactive UI
  return await runInteractive(orchestrator, config, exportPath);
}

/**
 * Run interactive UI mode
 * @param {ScanOrchestrator} orchestrator - Scan orchestrator
 * @param {Object} config - Scan configuration
 * @param {string} exportPath - Export file path
 * @returns {Promise<Array>} Discovered devices
 */
async function runInteractive(orchestrator, config, exportPath) {
  return new Promise((resolve) => {
    const handleExit = (devices) => {
      // Export if requested
      if (exportPath && devices.length > 0) {
        try {
          const format = exportPath.endsWith('.csv') ? 'csv' : 'json';
          const output = format === 'csv' ? formatCSV(devices) : formatJSON(devices);
          writeFileSync(exportPath, output, 'utf8');
          console.log(`\nResults exported to ${exportPath}`);
        } catch (error) {
          console.error(`Failed to export results: ${error.message}`);
        }
      }

      resolve(devices);
    };

    // Render Ink UI
    render(
      React.createElement(App, {
        orchestrator,
        config,
        onExit: handleExit,
      })
    );
  });
}

/**
 * Run in headless mode (no UI)
 * @param {ScanOrchestrator} orchestrator - Scan orchestrator
 * @param {Object} config - Scan configuration
 * @param {string} format - Output format
 * @param {string} exportPath - Export file path
 * @returns {Promise<Array>} Discovered devices
 */
async function runHeadless(orchestrator, config, format, exportPath) {
  console.log('Initializing scanner...');

  // Initialize
  const validation = await orchestrator.initialize();

  if (!validation.ready) {
    console.error('Scanner initialization failed:');
    validation.errors.forEach((err) => console.error(`  - ${err}`));
    process.exit(1);
  }

  if (validation.warnings.length > 0) {
    validation.warnings.forEach((warn) => console.warn(`Warning: ${warn}`));
  }

  console.log('Starting scan...\n');

  // Start scan
  await orchestrator.start(config);

  // Get results
  const devices = orchestrator.getDevices();
  const stats = orchestrator.getStats();

  // Format output
  let output;
  switch (format) {
    case 'json':
      output = formatJSON(devices, stats);
      break;
    case 'csv':
      output = formatCSV(devices);
      break;
    case 'table':
      output = formatTable(devices);
      break;
    default:
      output = formatJSON(devices, stats);
  }

  // Export or print
  if (exportPath) {
    try {
      writeFileSync(exportPath, output, 'utf8');
      console.log(`\nResults exported to ${exportPath}`);
      console.log(formatSummary(devices, stats));
    } catch (error) {
      console.error(`Failed to export results: ${error.message}`);
    }
  } else {
    console.log(output);
  }

  return devices;
}

export default startScan;
