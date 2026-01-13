#!/usr/bin/env node

/**
 * Test privilege detection - helps debug Windows admin detection issues
 */

console.log('='.repeat(60));
console.log('Privilege Detection Test');
console.log('='.repeat(60));
console.log(`Platform: ${process.platform}`);
console.log(`Node Version: ${process.version}`);
console.log(`Username: ${process.env.USERNAME || process.env.USER}`);
console.log(`CWD: ${process.cwd()}`);
console.log('='.repeat(60));

if (process.platform === 'win32') {
  console.log('\nWindows Privilege Tests:');
  console.log('-'.repeat(60));
  
  // Test 1: net session command
  console.log('\nTest 1: net session command');
  try {
    const { execSync } = require('child_process');
    const output = execSync('net session 2>&1', { 
      stdio: 'pipe',
      windowsHide: true,
      encoding: 'utf8'
    });
    console.log('✓ SUCCESS - You have administrator privileges');
    console.log('Output:', output.substring(0, 200));
  } catch (error) {
    console.log('✗ FAILED');
    console.log('Error message:', error.message);
    console.log('Exit code:', error.status);
    const errorOutput = error.stdout || error.stderr || error.message;
    console.log('Error output:', errorOutput);
    
    if (errorOutput.includes('System error 5') || errorOutput.includes('Access is denied')) {
      console.log('→ Diagnosis: No administrator privileges (Access Denied)');
    } else if (errorOutput.includes('not recognized')) {
      console.log('→ Diagnosis: Command not found');
    } else {
      console.log('→ Diagnosis: Unknown error');
    }
  }
  
  // Test 2: Write to Windows temp
  console.log('\nTest 2: Write to Windows\\Temp');
  try {
    const fs = require('fs');
    const path = require('path');
    const testFile = path.join(process.env.WINDIR || 'C:\\Windows', 'Temp', `.nscan_test_${Date.now()}`);
    console.log('Test file:', testFile);
    fs.writeFileSync(testFile, 'test');
    fs.unlinkSync(testFile);
    console.log('✓ SUCCESS - Can write to Windows\\Temp');
  } catch (error) {
    console.log('✗ FAILED - Cannot write to Windows\\Temp');
    console.log('Error:', error.message);
  }
  
  // Test 3: Check environment variables
  console.log('\nTest 3: Environment indicators');
  console.log('USERDOMAIN:', process.env.USERDOMAIN);
  console.log('SESSIONNAME:', process.env.SESSIONNAME);
  console.log('COMPUTERNAME:', process.env.COMPUTERNAME);
  
} else {
  // Unix-like system
  console.log('\nUnix Privilege Test:');
  console.log('-'.repeat(60));
  if (process.getuid) {
    const uid = process.getuid();
    console.log(`UID: ${uid}`);
    if (uid === 0) {
      console.log('✓ Running as root');
    } else {
      console.log('✗ Not running as root');
    }
  } else {
    console.log('✗ getuid() not available');
  }
}

console.log('\n' + '='.repeat(60));
console.log('Test Complete');
console.log('='.repeat(60));

// Now test the actual hasPrivileges function
console.log('\nTesting hasPrivileges() function from CommandRunner.js:');
console.log('-'.repeat(60));

import('./src/utils/CommandRunner.js').then(module => {
  const hasPrivileges = module.hasPrivileges;
  const result = hasPrivileges();
  console.log(`Result: ${result}`);
  if (result) {
    console.log('✓ hasPrivileges() returned TRUE - scan should work');
  } else {
    console.log('✗ hasPrivileges() returned FALSE - scan will be blocked');
    if (process.platform === 'win32') {
      console.log('\nTo fix: Right-click Command Prompt and select "Run as administrator"');
    } else {
      console.log('\nTo fix: Run with sudo');
    }
  }
}).catch(err => {
  console.error('Error loading CommandRunner:', err.message);
});
