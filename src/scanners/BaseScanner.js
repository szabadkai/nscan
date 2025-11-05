/**
 * Base scanner class - Abstract base for all scanner implementations
 * Provides event emitter functionality and common interface
 */

import { EventEmitter } from 'events';
import eventBus, { Events } from '../utils/EventBus.js';

/**
 * Abstract base class for all network scanners
 * Scanners emit events to the global event bus for decoupled communication
 */
export default class BaseScanner extends EventEmitter {
  /**
   * Create a scanner
   * @param {string} name - Scanner name
   * @param {Object} options - Scanner options
   */
  constructor(name, options = {}) {
    super();

    this.name = name;
    this.options = options;
    this.running = false;
    this.startTime = null;
    this.endTime = null;

    // Devices discovered by this scanner
    this.devices = new Map();

    // Scanner-specific event prefix
    this.eventPrefix = name.toLowerCase();
  }

  /**
   * Start the scanner
   * Must be implemented by subclasses
   * @param {Object} config - Scan configuration
   * @returns {Promise<void>}
   */
  async start(config) {
    throw new Error(`${this.name}.start() must be implemented by subclass`);
  }

  /**
   * Stop the scanner
   * Must be implemented by subclasses
   * @returns {Promise<void>}
   */
  async stop() {
    throw new Error(`${this.name}.stop() must be implemented by subclass`);
  }

  /**
   * Get scan results
   * @returns {Array<Object>} Array of discovered devices
   */
  getResults() {
    return Array.from(this.devices.values());
  }

  /**
   * Get scan statistics
   * @returns {Object} Scan statistics
   */
  getStats() {
    return {
      name: this.name,
      running: this.running,
      deviceCount: this.devices.size,
      startTime: this.startTime,
      endTime: this.endTime,
      duration: this.endTime
        ? (this.endTime - this.startTime) / 1000
        : this.startTime
        ? (Date.now() - this.startTime) / 1000
        : 0,
    };
  }

  /**
   * Mark scanner as started
   */
  _onStart() {
    this.running = true;
    this.startTime = Date.now();
    this.endTime = null;

    // Emit to both local and global event bus
    this.emit('start');
    eventBus.emit(`${this.eventPrefix}:start`, { scanner: this.name });
  }

  /**
   * Mark scanner as completed
   */
  _onComplete() {
    this.running = false;
    this.endTime = Date.now();

    // Emit to both local and global event bus
    this.emit('complete', this.getResults());
    eventBus.emit(`${this.eventPrefix}:complete`, {
      scanner: this.name,
      devices: this.getResults(),
      stats: this.getStats(),
    });
  }

  /**
   * Report an error
   * @param {Error} error - Error object
   */
  _onError(error) {
    this.emit('error', error);
    eventBus.emit(Events.SCAN_ERROR, {
      scanner: this.name,
      error: error.message,
    });
  }

  /**
   * Report progress
   * @param {Object} progress - Progress information
   */
  _onProgress(progress) {
    this.emit('progress', progress);
    eventBus.emit(Events.SCAN_PROGRESS, {
      scanner: this.name,
      ...progress,
    });
  }

  /**
   * Register a discovered device
   * @param {Object} device - Device information
   */
  _addDevice(device) {
    const key = device.ip || device.mac;
    if (!key) {
      console.warn('Device without IP or MAC:', device);
      return;
    }

    // Check if device already exists
    const existing = this.devices.get(key);

    if (existing) {
      // Merge new data with existing
      const updated = { ...existing, ...device };
      this.devices.set(key, updated);

      // Emit update event
      this.emit('device-updated', updated);
      eventBus.emit(Events.DEVICE_UPDATED, {
        scanner: this.name,
        device: updated,
      });
    } else {
      // New device
      this.devices.set(key, device);

      // Emit discovery event
      this.emit('device-discovered', device);
      eventBus.emit(Events.DEVICE_DISCOVERED, {
        scanner: this.name,
        device,
      });
    }
  }

  /**
   * Check if scanner is currently running
   * @returns {boolean} True if running
   */
  isRunning() {
    return this.running;
  }

  /**
   * Reset scanner state
   */
  reset() {
    this.devices.clear();
    this.running = false;
    this.startTime = null;
    this.endTime = null;
  }
}
