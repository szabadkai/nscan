/**
 * Main App Component - Orchestrates the entire UI
 */

import React, { useState, useEffect } from 'react';
import { Box, Text, useApp, useInput } from 'ink';
import { writeFileSync } from 'fs';
import Header from './Header.js';
import ScanProgress from './ScanProgress.js';
import DeviceList from './DeviceList.js';
import StatusBar from './StatusBar.js';
import DetailView from './DetailView.js';
import LoadingSpinner from './LoadingSpinner.js';
import ErrorDisplay from './ErrorDisplay.js';
import eventBus, { Events } from '../utils/EventBus.js';
import { dataAggregator } from '../analyzers/DataAggregator.js';
import { formatJSON, formatCSV } from '../utils/OutputFormatter.js';

/**
 * Main application component
 * @param {Object} props - Component props
 * @param {Object} props.orchestrator - ScanOrchestrator instance
 * @param {Object} props.config - Scan configuration
 * @param {Function} props.onExit - Exit callback
 */
const App = ({ orchestrator, config, onExit }) => {
  const { exit } = useApp();

  // State
  const [scanning, setScanning] = useState(false);
  const [initializing, setInitializing] = useState(true);
  const [devices, setDevices] = useState([]);
  const [phase, setPhase] = useState('Initializing');
  const [duration, setDuration] = useState(0);
  const [progress, setProgress] = useState(0);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const [showDetail, setShowDetail] = useState(false);
  const [status, setStatus] = useState('Initializing...');
  const [error, setError] = useState(null);
  const [missingDeps, setMissingDeps] = useState([]);

  /**
   * Initialize and start scanning
   */
  useEffect(() => {
    let durationInterval;

    const initialize = async () => {
      try {
        // Initialize orchestrator
        const validation = await orchestrator.initialize();

        if (!validation.ready) {
          setError(validation.errors.join('\n'));
          setMissingDeps(validation.missing || []);
          setInitializing(false);
          return;
        }

        // Show warnings if any
        if (validation.warnings.length > 0) {
          // Just log warnings, don't block
          validation.warnings.forEach((w) => console.warn(w));
        }

        setInitializing(false);
        setScanning(true);
        setStatus('Scanning network...');

        // Start scanning
        await orchestrator.start(config);
      } catch (err) {
        setError(err.message);
        setScanning(false);
        setInitializing(false);
      }
    };

    // Set up event listeners
    const unsubscribers = [];

    unsubscribers.push(
      eventBus.subscribe(Events.SCAN_STARTED, () => {
        setScanning(true);
        setStatus('Scan started');
      })
    );

    unsubscribers.push(
      eventBus.subscribe(Events.SCAN_COMPLETED, (data) => {
        setScanning(false);
        setStatus('Scan complete');
        setProgress(100);
      })
    );

    unsubscribers.push(
      eventBus.subscribe(Events.SCAN_PHASE_CHANGE, (data) => {
        setPhase(data.name);
      })
    );

    unsubscribers.push(
      eventBus.subscribe(Events.SCAN_PROGRESS, (data) => {
        if (data.scanned && data.total) {
          setProgress(Math.round((data.scanned / data.total) * 100));
        }
      })
    );

    unsubscribers.push(
      eventBus.subscribe(Events.DEVICE_DISCOVERED, () => {
        // Update device list
        setDevices([...dataAggregator.getDevices()]);
      })
    );

    unsubscribers.push(
      eventBus.subscribe(Events.DEVICE_UPDATED, () => {
        // Update device list
        setDevices([...dataAggregator.getDevices()]);
      })
    );

    unsubscribers.push(
      eventBus.subscribe(Events.DEVICE_ENRICHED, () => {
        // Update device list
        setDevices([...dataAggregator.getDevices()]);
      })
    );

    unsubscribers.push(
      eventBus.subscribe(Events.SCAN_ERROR, (data) => {
        setError(data.error);
        setScanning(false);
      })
    );

    // Start duration counter
    durationInterval = setInterval(() => {
      if (scanning) {
        setDuration((d) => d + 1);
      }
    }, 1000);

    // Start initialization
    initialize();

    // Cleanup
    return () => {
      unsubscribers.forEach((unsub) => unsub());
      if (durationInterval) {
        clearInterval(durationInterval);
      }
    };
  }, []); // Empty dependency array - run once on mount

  /**
   * Handle rescan
   */
  const handleRescan = async () => {
    try {
      // Clear existing data
      setDevices([]);
      setProgress(0);
      setDuration(0);
      setSelectedIndex(-1);
      setShowDetail(false);
      setPhase('Initializing');
      setStatus('Restarting scan...');
      setScanning(true);

      // Clear data aggregator
      dataAggregator.clear();

      // Stop orchestrator if running
      if (orchestrator.isRunning && orchestrator.isRunning()) {
        await orchestrator.stop();
      }

      // Restart orchestrator
      await orchestrator.start(config);
    } catch (err) {
      setError(err.message);
      setScanning(false);
    }
  };

  /**
   * Handle keyboard input
   */
  useInput((input, key) => {
    // Q or Escape to quit
    if (input === 'q' || input === 'Q' || key.escape) {
      handleExit();
      return;
    }

    // Ctrl+C to stop scanning
    if (key.ctrl && input === 'c') {
      if (scanning) {
        orchestrator.stop();
        setScanning(false);
        setStatus('Scan stopped by user');
      } else {
        handleExit();
      }
      return;
    }

    // R to rescan (when scan is complete)
    if ((input === 'r' || input === 'R') && !scanning) {
      handleRescan();
      return;
    }

    // E to export (when scan is complete)
    if ((input === 'e' || input === 'E') && !scanning && devices.length > 0) {
      try {
        const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0];
        const filename = `nscan-export-${timestamp}.json`;

        const output = formatJSON(
          devices.map(d => d.toObject ? d.toObject() : d),
          orchestrator.getStats()
        );

        writeFileSync(filename, output, 'utf8');
        setStatus(`✓ Exported ${devices.length} devices to ${filename}`);
      } catch (error) {
        setStatus(`✗ Export failed: ${error.message}`);
      }
      return;
    }

    // Arrow keys to navigate devices
    if (key.upArrow && selectedIndex > 0) {
      setSelectedIndex(selectedIndex - 1);
      setShowDetail(true);
    }

    if (key.downArrow && selectedIndex < devices.length - 1) {
      setSelectedIndex(selectedIndex + 1);
      setShowDetail(true);
    }

    // Enter to toggle detail view
    if (key.return) {
      setShowDetail(!showDetail);
    }
  });

  /**
   * Handle exit
   */
  const handleExit = async () => {
    if (scanning) {
      await orchestrator.stop();
    }
    if (onExit) {
      onExit(devices);
    }
    exit();
  };

  /**
   * Render error state
   */
  if (error) {
    return (
      <Box flexDirection="column" padding={1}>
        <Header version="1.0.0" />
        <ErrorDisplay error={error} missing={missingDeps} />
      </Box>
    );
  }

  /**
   * Render initializing state
   */
  if (initializing) {
    return (
      <Box flexDirection="column" padding={1}>
        <Header version="1.0.0" />
        <LoadingSpinner message="Initializing scanner..." />
      </Box>
    );
  }

  /**
   * Render main UI
   */
  return (
    <Box flexDirection="column" padding={1}>
      <Header version="1.0.0" />

      <ScanProgress
        scanning={scanning}
        phase={phase}
        deviceCount={devices.length}
        duration={duration}
        progress={progress}
      />

      <DeviceList devices={devices} selectedIndex={selectedIndex} />

      {showDetail && selectedIndex >= 0 && selectedIndex < devices.length && (
        <DetailView device={devices[selectedIndex]} />
      )}

      <StatusBar status={status} scanning={scanning} deviceCount={devices.length} />
    </Box>
  );
};

export default App;
