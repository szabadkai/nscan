#!/usr/bin/env node

/**
 * CLI entry point - Handles command-line arguments and starts the scanner
 */

import { Command } from 'commander';
import chalk from 'chalk';
import { startScan } from './index.js';
import { hasPrivileges } from './utils/CommandRunner.js';
import { readFileSync } from 'fs';
import { getUserConfigPath } from './utils/paths.js';

// Read package.json for version
const packageJson = JSON.parse(
  readFileSync(new URL('../package.json', import.meta.url), 'utf8')
);

const program = new Command();

/**
 * Check for required privileges
 */
function checkPrivileges() {
  if (!hasPrivileges()) {
    console.error(chalk.red('\n✗ Error: Insufficient privileges\n'));
    console.error('This tool requires root/administrator privileges to access network interfaces.');
    
    if (process.platform === 'win32') {
      console.error(chalk.cyan('\nPlease run as Administrator:'));
      console.error(chalk.yellow('  1. Right-click Command Prompt or PowerShell'));
      console.error(chalk.yellow('  2. Select "Run as administrator"'));
      console.error(chalk.yellow('  3. Run: nscan\n'));
    } else {
      console.error(chalk.cyan('\nPlease run with sudo:'));
      console.error(chalk.yellow('  sudo nscan\n'));
    }
    
    process.exit(1);
  }
}

/**
 * Load user configuration file if it exists
 */
function loadUserConfig() {
  try {
    const configPath = getUserConfigPath();
    const config = JSON.parse(readFileSync(configPath, 'utf8'));
    return config;
  } catch {
    // Config file doesn't exist or is invalid, use defaults
    return {};
  }
}

/**
 * Main CLI setup
 */
program
  .name('nscan')
  .description('Modern network scanner with comprehensive device discovery')
  .version(packageJson.version)
  .option('-r, --range <cidr>', 'Network range to scan (e.g., 192.168.1.0/24)')
  .option('-i, --interface <name>', 'Network interface to use')
  .option('-p, --passive', 'Passive mode only (no active probes)')
  .option('-w, --watch', 'Continuous monitoring mode')
  .option('-e, --export <file>', 'Export results to file')
  .option('-f, --format <type>', 'Output format: interactive, json, csv, table', 'interactive')
  .option('-v, --verbose', 'Verbose output')
  .option('--no-os', 'Skip OS detection (faster)')
  .option('--fast', 'Fast mode (equivalent to --scan-level quick)')
  .option('-l, --scan-level <level>', 'Scan depth: quick, standard, thorough', 'standard')
  .option('-t, --timeout <seconds>', 'Scan timeout per host', '30')
  .option('--ipv6', 'Enable IPv6 scanning (auto-detected by default)')
  .option('--no-ipv6', 'Disable IPv6 scanning')
  .option('--demo', 'Demo mode (fake data for testing UI without sudo/nmap)')
  .action(async (options) => {
    // Skip privilege check in demo mode
    if (!options.demo) {
      checkPrivileges();
    }

    // Load user config and merge with CLI options
    const userConfig = loadUserConfig();
    const config = { ...userConfig, ...options };

    // Parse timeout
    config.timeout = parseInt(config.timeout, 10);

    // Handle fast mode as alias for quick scan level
    if (config.fast) {
      config.scanLevel = 'quick';
    }

    // Validate scan level
    const validLevels = ['quick', 'standard', 'thorough'];
    if (!validLevels.includes(config.scanLevel)) {
      console.error(
        chalk.red(`\n✗ Invalid scan level: ${config.scanLevel}`)
      );
      console.error(`Valid levels: ${validLevels.join(', ')}\n`);
      process.exit(1);
    }

    // Validate format
    const validFormats = ['interactive', 'json', 'csv', 'table'];
    if (!validFormats.includes(config.format)) {
      console.error(
        chalk.red(`\n✗ Invalid format: ${config.format}`)
      );
      console.error(`Valid formats: ${validFormats.join(', ')}\n`);
      process.exit(1);
    }

    // Show banner
    if (config.format === 'interactive') {
      console.clear();
    }

    try {
      // Start scanning with cleanup registration
      const devices = await startScan(config, registerCleanup);

      // Exit with success
      process.exit(0);
    } catch (error) {
      console.error(chalk.red(`\n✗ Error: ${error.message}\n`));

      if (config.verbose && error.stack) {
        console.error(chalk.dim(error.stack));
      }

      process.exit(1);
    }
  });

/**
 * Display examples
 */
program.addHelpText(
  'after',
  `
${chalk.bold('Scan Levels:')}
  ${chalk.cyan('quick')}      Fast ARP/NDP + mDNS/SSDP discovery, minimal ports (5s)
  ${chalk.cyan('standard')}   Full discovery + common ports + OS detection (30s) ${chalk.dim('[default]')}
  ${chalk.cyan('thorough')}   All discovery + top 1000 ports + deep OS fingerprinting (90s)

${chalk.bold('Examples:')}
  ${chalk.cyan('sudo nscan')}
    Interactive mode with auto-detected network (standard scan)

  ${chalk.cyan('sudo nscan --scan-level quick')}
    Fast discovery scan (ARP, NDP, mDNS, SSDP only)

  ${chalk.cyan('sudo nscan --scan-level thorough')}
    Deep scan with full port coverage and OS fingerprinting

  ${chalk.cyan('sudo nscan --range 192.168.1.0/24')}
    Scan specific network range

  ${chalk.cyan('sudo nscan --passive --watch')}
    Passive monitoring mode (continuous, no active probes)

  ${chalk.cyan('sudo nscan --export devices.json')}
    Export results to JSON file

  ${chalk.cyan('sudo nscan --format csv --export devices.csv')}
    Export results as CSV

  ${chalk.cyan('sudo nscan --no-ipv6')}
    Disable IPv6 scanning

  ${chalk.cyan('nscan --demo')}
    Run in demo mode (no sudo/nmap required, fake data for testing UI)

${chalk.bold('Discovery Methods:')}
  ${chalk.green('•')} ARP scanning (IPv4 neighbors)
  ${chalk.green('•')} NDP scanning (IPv6 neighbors)
  ${chalk.green('•')} mDNS/Bonjour (Apple, Chromecast, printers, IoT)
  ${chalk.green('•')} SSDP/UPnP (smart TVs, media devices, routers)
  ${chalk.green('•')} NetBIOS/SMB (Windows machines)
  ${chalk.green('•')} DHCP snooping (hostnames from DHCP traffic)
  ${chalk.green('•')} Nmap service/OS detection

${chalk.bold('Notes:')}
  - Requires ${chalk.yellow('sudo')} or administrator privileges (except demo mode)
  - Requires ${chalk.yellow('nmap')} to be installed (except demo mode)
  - Optional: ${chalk.yellow('tcpdump')}, ${chalk.yellow('arp-scan')} for better results
  - IPv6 is enabled by default on dual-stack networks
  - Use ${chalk.cyan('--demo')} flag to test the UI without network scanning
`
);

// Global cleanup handler
let cleanupCallbacks = [];

export function registerCleanup(callback) {
  cleanupCallbacks.push(callback);
}

async function cleanup() {
  for (const callback of cleanupCallbacks) {
    try {
      await callback();
    } catch (error) {
      // Ignore cleanup errors
    }
  }
  cleanupCallbacks = [];
}

// Handle SIGINT gracefully
process.on('SIGINT', async () => {
  console.log('\n\nScan interrupted by user...');
  await cleanup();
  process.exit(0);
});

// Handle SIGTERM
process.on('SIGTERM', async () => {
  console.log('\n\nReceived termination signal...');
  await cleanup();
  process.exit(0);
});

// Handle uncaught errors
process.on('uncaughtException', async (error) => {
  console.error(chalk.red('\n✗ Uncaught error:'), error.message);
  await cleanup();
  process.exit(1);
});

process.on('unhandledRejection', async (reason) => {
  console.error(chalk.red('\n✗ Unhandled rejection:'), reason);
  await cleanup();
  process.exit(1);
});

// Parse command line arguments
program.parse(process.argv);
