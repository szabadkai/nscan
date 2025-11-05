/**
 * Path utilities for ESM and PKG compatibility
 * Handles path resolution in both development and compiled executable environments
 */

import { fileURLToPath } from 'url';
import { dirname, join, resolve } from 'path';

/**
 * Detect if running inside a PKG compiled executable
 * @returns {boolean} True if running in PKG environment
 */
export function isPkg() {
  return typeof process.pkg !== 'undefined';
}

/**
 * Get the directory name for the current module (ESM replacement for __dirname)
 * @param {string} importMetaUrl - import.meta.url from the calling module
 * @returns {string} Directory path
 */
export function getDirname(importMetaUrl) {
  return dirname(fileURLToPath(importMetaUrl));
}

/**
 * Get the file path for the current module (ESM replacement for __filename)
 * @param {string} importMetaUrl - import.meta.url from the calling module
 * @returns {string} File path
 */
export function getFilename(importMetaUrl) {
  return fileURLToPath(importMetaUrl);
}

/**
 * Get the project root directory
 * Works in both development and PKG environments
 * @returns {string} Project root path
 */
export function getProjectRoot() {
  if (isPkg()) {
    // In PKG, use the directory containing the executable
    return dirname(process.execPath);
  }

  // In development, go up from src/utils to root
  const currentDir = getDirname(import.meta.url);
  return resolve(currentDir, '..', '..');
}

/**
 * Resolve a path relative to the project root
 * @param {...string} paths - Path segments to join
 * @returns {string} Resolved absolute path
 */
export function resolveFromRoot(...paths) {
  return join(getProjectRoot(), ...paths);
}

/**
 * Get the path to a config file
 * @param {string} filename - Config filename
 * @returns {string} Config file path
 */
export function getConfigPath(filename) {
  return resolveFromRoot('config', filename);
}

/**
 * Get the user's home directory
 * @returns {string} Home directory path
 */
export function getHomeDir() {
  return process.env.HOME || process.env.USERPROFILE || '';
}

/**
 * Get the path to user's config file
 * @param {string} filename - Config filename
 * @returns {string} User config file path
 */
export function getUserConfigPath(filename = '.nscancfg.json') {
  return join(getHomeDir(), filename);
}
