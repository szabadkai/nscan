/**
 * Global event bus for cross-module communication
 * Simple event emitter for decoupled communication between scanners, analyzers, and UI
 */

import { EventEmitter } from 'events';

/**
 * Event types used throughout the application
 */
export const Events = {
  // Scanner events
  SCAN_STARTED: 'scan:started',
  SCAN_COMPLETED: 'scan:completed',
  SCAN_ERROR: 'scan:error',
  SCAN_PROGRESS: 'scan:progress',
  SCAN_PHASE_CHANGE: 'scan:phase_change',

  // Device events
  DEVICE_DISCOVERED: 'device:discovered',
  DEVICE_UPDATED: 'device:updated',
  DEVICE_ENRICHED: 'device:enriched',

  // Scanner-specific events
  ARP_SCAN_START: 'arp:scan_start',
  ARP_SCAN_COMPLETE: 'arp:scan_complete',
  NMAP_SCAN_START: 'nmap:scan_start',
  NMAP_SCAN_COMPLETE: 'nmap:scan_complete',
  TCPDUMP_START: 'tcpdump:start',
  TCPDUMP_PACKET: 'tcpdump:packet',
  TCPDUMP_STOP: 'tcpdump:stop',

  // Analysis events
  MANUFACTURER_RESOLVED: 'analysis:manufacturer',
  OS_DETECTED: 'analysis:os',
  USAGE_INFERRED: 'analysis:usage',

  // Application events
  APP_SHUTDOWN: 'app:shutdown',
  APP_ERROR: 'app:error',
};

/**
 * Global EventBus instance
 */
class EventBus extends EventEmitter {
  constructor() {
    super();
    // Increase max listeners to avoid warnings with multiple scanners
    this.setMaxListeners(50);
  }

  /**
   * Emit an event with optional data
   * @param {string} event - Event name
   * @param {*} data - Event data
   */
  emit(event, data) {
    super.emit(event, data);

    // Also emit to wildcard listeners
    super.emit('*', { event, data });
  }

  /**
   * Subscribe to an event
   * @param {string} event - Event name
   * @param {Function} handler - Event handler function
   * @returns {Function} Unsubscribe function
   */
  subscribe(event, handler) {
    this.on(event, handler);

    // Return unsubscribe function
    return () => {
      this.off(event, handler);
    };
  }

  /**
   * Subscribe to an event once
   * @param {string} event - Event name
   * @param {Function} handler - Event handler function
   * @returns {Function} Unsubscribe function
   */
  subscribeOnce(event, handler) {
    this.once(event, handler);

    // Return unsubscribe function
    return () => {
      this.off(event, handler);
    };
  }

  /**
   * Subscribe to all events (wildcard)
   * @param {Function} handler - Event handler function
   * @returns {Function} Unsubscribe function
   */
  subscribeAll(handler) {
    return this.subscribe('*', handler);
  }

  /**
   * Remove all listeners for an event
   * @param {string} event - Event name (optional, removes all if not specified)
   */
  clear(event) {
    if (event) {
      this.removeAllListeners(event);
    } else {
      this.removeAllListeners();
    }
  }

  /**
   * Get the count of listeners for an event
   * @param {string} event - Event name
   * @returns {number} Listener count
   */
  listenerCount(event) {
    return super.listenerCount(event);
  }
}

// Create and export singleton instance
const eventBus = new EventBus();

export default eventBus;
