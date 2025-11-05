/**
 * OS Detector - Parse and identify operating systems from various sources
 */

/**
 * Detect and normalize operating system information
 */
export default class OsDetector {
  constructor() {
    // OS pattern matching rules
    this.patterns = {
      // Windows
      windows: [
        /windows\s*(nt|xp|vista|7|8|10|11|server)?/i,
        /microsoft.*windows/i,
        /win32/i,
        /win64/i,
      ],

      // macOS
      macos: [
        /mac\s*os\s*x?/i,
        /darwin/i,
        /osx/i,
        /macos/i,
        /apple.*mac/i,
      ],

      // iOS
      ios: [/ios/i, /iphone/i, /ipad/i, /ipod/i],

      // Android
      android: [/android/i],

      // Linux
      linux: [
        /linux/i,
        /ubuntu/i,
        /debian/i,
        /fedora/i,
        /centos/i,
        /rhel/i,
        /suse/i,
        /arch/i,
        /mint/i,
      ],

      // FreeBSD/Unix
      bsd: [/freebsd/i, /openbsd/i, /netbsd/i, /unix/i],

      // Embedded/IoT
      embedded: [
        /embedded/i,
        /openwrt/i,
        /dd-wrt/i,
        /tomato/i,
        /busybox/i,
        /uclinux/i,
      ],
    };

    // Version extraction patterns
    this.versionPatterns = [
      // Windows versions
      /windows\s*(nt\s*)?(\d+\.?\d*)/i,
      /windows\s*(xp|vista|7|8|10|11)/i,

      // macOS versions
      /mac\s*os\s*x?\s*(\d+\.?\d*\.?\d*)/i,

      // iOS versions
      /ios\s*(\d+\.?\d*\.?\d*)/i,

      // Android versions
      /android\s*(\d+\.?\d*\.?\d*)/i,

      // Linux kernel versions
      /linux\s*(\d+\.?\d*\.?\d*)/i,

      // Generic version pattern
      /(\d+\.?\d*\.?\d*)/,
    ];
  }

  /**
   * Detect OS from various information sources
   * @param {Object} data - Device data containing potential OS info
   * @returns {Object} Detected OS information
   */
  detect(data) {
    const result = {
      os: null,
      osVersion: null,
      confidence: 0,
      source: null,
    };

    // Try to detect from explicit OS field
    if (data.os) {
      const detected = this._parseOsString(data.os);
      if (detected.os) {
        result.os = detected.os;
        result.osVersion = detected.version;
        result.confidence = 90;
        result.source = 'os-field';
        return result;
      }
    }

    // Try to detect from hostname
    if (data.hostname) {
      const detected = this._detectFromHostname(data.hostname);
      if (detected.os) {
        result.os = detected.os;
        result.osVersion = detected.version;
        result.confidence = 60;
        result.source = 'hostname';
        return result;
      }
    }

    // Try to detect from services/ports
    if (data.services || data.ports) {
      const detected = this._detectFromServices(data);
      if (detected.os) {
        result.os = detected.os;
        result.confidence = 50;
        result.source = 'services';
        return result;
      }
    }

    // Try to detect from manufacturer
    if (data.manufacturer) {
      const detected = this._detectFromManufacturer(data.manufacturer);
      if (detected.os) {
        result.os = detected.os;
        result.confidence = 40;
        result.source = 'manufacturer';
        return result;
      }
    }

    return result;
  }

  /**
   * Parse an OS string and extract normalized OS name and version
   * @param {string} osString - OS string to parse
   * @returns {Object} Parsed OS info
   */
  _parseOsString(osString) {
    const result = {
      os: null,
      version: null,
    };

    if (!osString) return result;

    const lower = osString.toLowerCase();

    // Match against patterns
    for (const [osType, patterns] of Object.entries(this.patterns)) {
      for (const pattern of patterns) {
        if (pattern.test(lower)) {
          result.os = this._normalizeOsName(osType, osString);

          // Try to extract version
          result.version = this._extractVersion(osString);

          return result;
        }
      }
    }

    // If no pattern matched, use the original string
    result.os = osString;
    result.version = this._extractVersion(osString);

    return result;
  }

  /**
   * Detect OS from hostname
   * @param {string} hostname - Hostname
   * @returns {Object} Detected OS info
   */
  _detectFromHostname(hostname) {
    const lower = hostname.toLowerCase();

    if (lower.includes('iphone') || lower.includes('ipad')) {
      return { os: 'iOS', version: null };
    }

    if (lower.includes('android')) {
      return { os: 'Android', version: null };
    }

    if (lower.includes('macbook') || lower.includes('mac')) {
      return { os: 'macOS', version: null };
    }

    if (lower.includes('windows') || lower.includes('win') || lower.includes('pc')) {
      return { os: 'Windows', version: null };
    }

    if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('debian')) {
      return { os: 'Linux', version: null };
    }

    return { os: null, version: null };
  }

  /**
   * Detect OS from services/ports
   * @param {Object} data - Device data with services/ports
   * @returns {Object} Detected OS info
   */
  _detectFromServices(data) {
    const ports = data.ports || [];
    const services = data.services || [];

    // Windows indicators
    if (ports.includes(3389) || ports.includes(445)) {
      // RDP or SMB
      return { os: 'Windows', version: null };
    }

    // macOS indicators
    if (ports.includes(5353)) {
      // mDNS (Bonjour)
      return { os: 'macOS', version: null };
    }

    // Linux indicators
    if (ports.includes(22) && !ports.includes(3389)) {
      // SSH but no RDP - likely Linux
      return { os: 'Linux', version: null };
    }

    // Check service names
    for (const service of services) {
      if (service.service) {
        const svcLower = service.service.toLowerCase();

        if (svcLower.includes('microsoft') || svcLower.includes('windows')) {
          return { os: 'Windows', version: null };
        }

        if (svcLower.includes('ssh') && svcLower.includes('openssh')) {
          return { os: 'Linux', version: null };
        }
      }
    }

    return { os: null, version: null };
  }

  /**
   * Detect OS from manufacturer
   * @param {string} manufacturer - Manufacturer name
   * @returns {Object} Detected OS info
   */
  _detectFromManufacturer(manufacturer) {
    const lower = manufacturer.toLowerCase();

    if (lower.includes('apple')) {
      // Could be macOS, iOS, or other Apple devices
      return { os: 'Apple Device', version: null };
    }

    if (lower.includes('microsoft')) {
      return { os: 'Windows', version: null };
    }

    if (lower.includes('raspberry') || lower.includes('pi')) {
      return { os: 'Linux', version: null };
    }

    return { os: null, version: null };
  }

  /**
   * Normalize OS name to standard format
   * @param {string} osType - Detected OS type
   * @param {string} original - Original string
   * @returns {string} Normalized OS name
   */
  _normalizeOsName(osType, original) {
    const nameMap = {
      windows: 'Windows',
      macos: 'macOS',
      ios: 'iOS',
      android: 'Android',
      linux: 'Linux',
      bsd: 'BSD',
      embedded: 'Embedded Linux',
    };

    return nameMap[osType] || original;
  }

  /**
   * Extract version number from string
   * @param {string} str - String containing version
   * @returns {string|null} Extracted version or null
   */
  _extractVersion(str) {
    if (!str) return null;

    for (const pattern of this.versionPatterns) {
      const match = str.match(pattern);
      if (match && match[1]) {
        return match[1];
      }
    }

    return null;
  }

  /**
   * Get OS family for a given OS
   * @param {string} os - OS name
   * @returns {string} OS family
   */
  getOsFamily(os) {
    if (!os) return 'Unknown';

    const lower = os.toLowerCase();

    if (lower.includes('windows')) return 'Windows';
    if (lower.includes('mac') || lower.includes('darwin')) return 'macOS';
    if (lower.includes('ios') || lower.includes('iphone')) return 'iOS';
    if (lower.includes('android')) return 'Android';
    if (lower.includes('linux') || lower.includes('ubuntu') || lower.includes('debian'))
      return 'Linux';
    if (lower.includes('bsd')) return 'BSD';

    return 'Other';
  }
}

// Export singleton instance
export const osDetector = new OsDetector();
