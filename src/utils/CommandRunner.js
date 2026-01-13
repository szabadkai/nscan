/**
 * Safe command execution utility with dependency checking
 */

import { spawn, exec } from 'child_process';
import { promisify } from 'util';

const execPromise = promisify(exec);

/**
 * Check if a command exists on the system
 * @param {string} command - Command name to check
 * @returns {Promise<boolean>} True if command exists
 */
export async function commandExists(command) {
  try {
    const checkCmd = process.platform === 'win32' ? 'where' : 'which';
    await execPromise(`${checkCmd} ${command}`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check for required system dependencies
 * @returns {Promise<Object>} Object with available commands
 */
export async function checkDependencies() {
  const commands = ['nmap', 'tcpdump', 'arp-scan', 'arp', 'ping'];
  const results = {};

  for (const cmd of commands) {
    results[cmd] = await commandExists(cmd);
  }

  return results;
}

/**
 * Get missing dependencies with installation instructions
 * @param {Object} deps - Dependency check results
 * @returns {Array<Object>} Array of missing dependencies with install info
 */
export function getMissingDependencies(deps) {
  const missing = [];
  const installInstructions = {
    nmap: {
      linux: 'sudo apt-get install nmap',
      darwin: 'brew install nmap',
      win32: 'Download from https://nmap.org/download.html',
    },
    tcpdump: {
      linux: 'sudo apt-get install tcpdump',
      darwin: 'Pre-installed on macOS',
      win32: 'Install WinPcap or Npcap',
    },
    'arp-scan': {
      linux: 'sudo apt-get install arp-scan',
      darwin: 'brew install arp-scan',
      win32: 'Not available (will use arp)',
    },
  };

  for (const [cmd, available] of Object.entries(deps)) {
    if (!available && installInstructions[cmd]) {
      missing.push({
        command: cmd,
        install: installInstructions[cmd][process.platform] || 'Not available',
      });
    }
  }

  return missing;
}

/**
 * Execute a command and return output as string
 * @param {string} command - Command to execute
 * @param {Object} options - Execution options
 * @returns {Promise<string>} Command output
 */
export async function executeCommand(command, options = {}) {
  const { timeout = 30000 } = options;

  try {
    const { stdout } = await execPromise(command, { timeout });
    return stdout;
  } catch (error) {
    throw new Error(`Command failed: ${error.message}`);
  }
}

/**
 * Spawn a command with streaming output
 * @param {string} command - Command to execute
 * @param {Array<string>} args - Command arguments
 * @param {Object} options - Spawn options
 * @returns {Object} Child process and event handlers
 */
export function spawnCommand(command, args = [], options = {}) {
  const child = spawn(command, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });

  const output = {
    stdout: '',
    stderr: '',
  };

  child.stdout.on('data', (data) => {
    output.stdout += data.toString();
  });

  child.stderr.on('data', (data) => {
    output.stderr += data.toString();
  });

  return {
    process: child,
    output,
    /**
     * Wait for command to complete
     * @returns {Promise<Object>} Exit code and output
     */
    wait: () =>
      new Promise((resolve, reject) => {
        child.on('close', (code) => {
          if (code === 0) {
            resolve({ code, ...output });
          } else {
            reject(new Error(`Command exited with code ${code}: ${output.stderr}`));
          }
        });

        child.on('error', (error) => {
          reject(error);
        });
      }),
  };
}

/**
 * Check if running with sufficient privileges
 * @returns {boolean} True if running as root/admin
 */
export function hasPrivileges() {
  if (process.platform === 'win32') {
    // On Windows, check if running with administrator elevation
    // Try multiple methods to detect admin privileges
    
    // Method 1: Try to access a Windows system file that requires admin
    try {
      const { execSync } = require('child_process');
      // 'net session' requires admin privileges to run
      execSync('net session 2>&1', { 
        stdio: 'pipe',
        windowsHide: true,
        encoding: 'utf8'
      });
      return true;
    } catch (error) {
      // Check if error is due to lack of privileges (not command not found)
      const errorOutput = error.message || error.toString();
      // If error contains "Access is denied" or "System error 5", no admin rights
      if (errorOutput.includes('System error 5') || 
          errorOutput.includes('Access is denied')) {
        return false;
      }
      // If command doesn't exist or other error, try fallback method
    }
    
    // Method 2: Fallback - check if we can write to Windows system directory
    try {
      const fs = require('fs');
      const path = require('path');
      const testFile = path.join(process.env.WINDIR || 'C:\\Windows', 'Temp', `.nscan_priv_test_${Date.now()}`);
      fs.writeFileSync(testFile, '');
      fs.unlinkSync(testFile);
      return true;
    } catch {
      return false;
    }
  }

  // On Unix-like systems, check if running as root
  return process.getuid && process.getuid() === 0;
}

/**
 * Kill a process and all its children
 * @param {ChildProcess} process - Process to kill
 * @param {string} signal - Signal to send (default: SIGTERM)
 */
export function killProcess(process, signal = 'SIGTERM') {
  if (!process || process.killed) {
    return;
  }

  try {
    if (process.platform === 'win32') {
      spawn('taskkill', ['/pid', process.pid, '/f', '/t']);
    } else {
      process.kill(signal);
    }
  } catch (error) {
    console.error(`Failed to kill process: ${error.message}`);
  }
}
