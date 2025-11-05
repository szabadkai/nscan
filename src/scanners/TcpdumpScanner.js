/**
 * Tcpdump Scanner - Passive network traffic monitoring
 * Captures and analyzes network packets to discover devices and services
 */

import BaseScanner from './BaseScanner.js';
import { spawnCommand } from '../utils/CommandRunner.js';
import { normalizeMac } from '../utils/NetworkUtils.js';
import eventBus, { Events } from '../utils/EventBus.js';

/**
 * Tcpdump Scanner for passive network discovery
 * Monitors network traffic without sending any packets
 */
export default class TcpdumpScanner extends BaseScanner {
  constructor(options = {}) {
    super('TcpdumpScanner', options);
    this.process = null;
    this.buffer = '';
  }

  /**
   * Start tcpdump capture
   * @param {Object} config - Scan configuration
   * @param {string} config.interface - Network interface to monitor
   * @param {number} config.timeout - Capture timeout in seconds (0 = infinite)
   */
  async start(config) {
    this._onStart();

    try {
      const { interface: iface, timeout = 0 } = config;

      // Build tcpdump command
      // -n: Don't resolve hostnames
      // -e: Print link-level header (MAC addresses)
      // -l: Line buffered output
      // -q: Quick/quiet output
      const args = ['-n', '-e', '-l', '-q'];

      if (iface) {
        args.push('-i', iface);
      }

      // Start tcpdump process
      const spawned = spawnCommand('tcpdump', args);
      this.process = spawned.process;

      // Process output line by line
      this.process.stdout.on('data', (data) => {
        this._processOutput(data.toString());
      });

      this.process.stderr.on('data', (data) => {
        // tcpdump writes info to stderr, parse it for useful info
        const line = data.toString().trim();
        if (line && !line.includes('listening on') && !line.includes('packets')) {
          console.error('tcpdump stderr:', line);
        }
      });

      this.process.on('error', (error) => {
        this._onError(error);
      });

      this.process.on('close', (code) => {
        if (this.running) {
          this._onComplete();
        }
      });

      // Emit start event
      eventBus.emit(Events.TCPDUMP_START, { scanner: this.name });

      // Set timeout if specified
      if (timeout > 0) {
        setTimeout(() => {
          this.stop();
        }, timeout * 1000);
      }
    } catch (error) {
      this._onError(error);
      throw error;
    }
  }

  /**
   * Stop tcpdump capture
   */
  async stop() {
    if (this.process && !this.process.killed) {
      this.process.kill('SIGTERM');
      eventBus.emit(Events.TCPDUMP_STOP, { scanner: this.name });
    }

    if (this.running) {
      this._onComplete();
    }
  }

  /**
   * Process tcpdump output line by line
   * @param {string} data - Output data chunk
   */
  _processOutput(data) {
    this.buffer += data;

    // Process complete lines
    const lines = this.buffer.split('\n');
    this.buffer = lines.pop() || ''; // Keep incomplete line in buffer

    for (const line of lines) {
      if (line.trim()) {
        this._parseLine(line);
      }
    }
  }

  /**
   * Parse a single tcpdump output line
   * Example: 12:34:56.789 00:11:22:33:44:55 > 66:77:88:99:aa:bb, ethertype IPv4, IP 192.168.1.100.12345 > 192.168.1.1.80: tcp 0
   * @param {string} line - Tcpdump output line
   */
  _parseLine(line) {
    try {
      // Extract MAC addresses
      const macMatch = line.match(/([\da-fA-F:]{17})\s+>\s+([\da-fA-F:]{17})/);

      // Extract IP addresses
      const ipMatch = line.match(
        /IP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\.?\d*\s+>\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/
      );

      // Extract protocol
      const protocolMatch = line.match(/ethertype\s+(\w+)/i);

      if (macMatch && ipMatch) {
        const [, srcMac, dstMac] = macMatch;
        const [, srcIp, dstIp] = ipMatch;
        const protocol = protocolMatch ? protocolMatch[1] : 'Unknown';

        // Add source device
        this._addDevice({
          ip: srcIp,
          mac: normalizeMac(srcMac),
          lastSeen: new Date().toISOString(),
          source: 'tcpdump',
        });

        // Add destination device (if not broadcast)
        if (!dstMac.startsWith('ff:ff:ff')) {
          this._addDevice({
            ip: dstIp,
            mac: normalizeMac(dstMac),
            lastSeen: new Date().toISOString(),
            source: 'tcpdump',
          });
        }

        // Emit packet event for further analysis
        eventBus.emit(Events.TCPDUMP_PACKET, {
          srcIp,
          srcMac: normalizeMac(srcMac),
          dstIp,
          dstMac: normalizeMac(dstMac),
          protocol,
          raw: line,
        });
      }
    } catch (error) {
      // Silently ignore parse errors for malformed lines
      // console.error('Error parsing tcpdump line:', error.message);
    }
  }
}
