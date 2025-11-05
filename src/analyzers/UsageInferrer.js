/**
 * Usage Inferrer - Infers device type and usage from available data
 * Analyzes manufacturer, OS, hostname, ports, and services to determine device purpose
 */

/**
 * Device usage categories
 */
export const UsageTypes = {
  ROUTER: 'Router/Gateway',
  SWITCH: 'Switch',
  ACCESS_POINT: 'Access Point',
  SERVER: 'Server',
  COMPUTER: 'Computer/Workstation',
  LAPTOP: 'Laptop',
  MOBILE: 'Mobile Device',
  IOT: 'IoT Device',
  SMART_HOME: 'Smart Home Device',
  PRINTER: 'Printer/Scanner',
  TV_MEDIA: 'TV/Media Device',
  GAMING: 'Gaming Console',
  STORAGE: 'Storage/NAS',
  CAMERA: 'Camera/Security',
  UNKNOWN: 'Unknown',
};

/**
 * Infer device usage and type from available information
 */
export default class UsageInferrer {
  constructor() {
    // Manufacturer patterns for device types
    this.manufacturerPatterns = {
      [UsageTypes.ROUTER]: [
        'cisco',
        'juniper',
        'netgear',
        'tp-link',
        'asus',
        'linksys',
        'ubiquiti',
        'd-link',
        'mikrotik',
      ],
      [UsageTypes.MOBILE]: ['apple', 'samsung', 'google', 'huawei', 'xiaomi', 'oneplus'],
      [UsageTypes.IOT]: ['raspberry', 'espressif', 'arduino', 'texas instruments'],
      [UsageTypes.PRINTER]: ['hp', 'canon', 'epson', 'brother', 'lexmark', 'xerox'],
      [UsageTypes.TV_MEDIA]: ['samsung', 'lg', 'sony', 'roku', 'amazon'],
      [UsageTypes.STORAGE]: ['synology', 'qnap', 'western digital', 'seagate'],
      [UsageTypes.CAMERA]: ['hikvision', 'dahua', 'axis', 'nest', 'ring'],
    };

    // Hostname patterns for device types
    this.hostnamePatterns = {
      [UsageTypes.ROUTER]: /router|gateway|gw|firewall/i,
      [UsageTypes.SWITCH]: /switch|sw\d+/i,
      [UsageTypes.ACCESS_POINT]: /ap\d+|access[-_]?point|wifi/i,
      [UsageTypes.SERVER]: /server|srv|web|mail|db|database/i,
      [UsageTypes.COMPUTER]: /desktop|pc|workstation|computer/i,
      [UsageTypes.LAPTOP]: /laptop|notebook|macbook/i,
      [UsageTypes.MOBILE]: /iphone|ipad|android|mobile|phone|tablet/i,
      [UsageTypes.IOT]: /esp|arduino|pi|iot|sensor/i,
      [UsageTypes.SMART_HOME]: /nest|hue|alexa|echo|google[-_]?home/i,
      [UsageTypes.PRINTER]: /printer|print|scanner|scan/i,
      [UsageTypes.TV_MEDIA]: /tv|roku|chromecast|firestick|appletv/i,
      [UsageTypes.GAMING]: /xbox|playstation|ps\d+|nintendo|switch/i,
      [UsageTypes.STORAGE]: /nas|storage|fileserver/i,
      [UsageTypes.CAMERA]: /camera|cam\d+|ipcam|security/i,
    };

    // Port-based indicators
    this.portIndicators = {
      [UsageTypes.ROUTER]: [53, 67, 68], // DNS, DHCP
      [UsageTypes.SERVER]: [80, 443, 8080, 8443, 22], // HTTP/HTTPS/SSH
      [UsageTypes.COMPUTER]: [445, 3389, 5900], // SMB, RDP, VNC
      [UsageTypes.PRINTER]: [631, 9100, 515], // IPP, JetDirect, LPD
      [UsageTypes.STORAGE]: [139, 445, 2049, 873], // SMB, NFS, rsync
      [UsageTypes.IOT]: [1883, 8883], // MQTT
      [UsageTypes.CAMERA]: [554, 8000, 8080], // RTSP, HTTP
    };
  }

  /**
   * Infer device usage from all available data
   * @param {Object} device - Device data
   * @returns {Object} Inferred usage with confidence
   */
  infer(device) {
    const scores = {};

    // Initialize scores for all types
    for (const type of Object.values(UsageTypes)) {
      scores[type] = 0;
    }

    // Analyze manufacturer
    if (device.manufacturer) {
      this._scoreByManufacturer(device.manufacturer, scores);
    }

    // Analyze hostname
    if (device.hostname) {
      this._scoreByHostname(device.hostname, scores);
    }

    // Analyze ports
    if (device.ports && device.ports.length > 0) {
      this._scoreByPorts(device.ports, scores);
    }

    // Analyze OS
    if (device.os) {
      this._scoreByOS(device.os, scores);
    }

    // Find the type with highest score
    let maxScore = 0;
    let bestType = UsageTypes.UNKNOWN;

    for (const [type, score] of Object.entries(scores)) {
      if (score > maxScore) {
        maxScore = score;
        bestType = type;
      }
    }

    // Calculate confidence (0-100)
    const confidence = Math.min((maxScore / 10) * 100, 100);

    return {
      usage: bestType,
      confidence,
      scores,
    };
  }

  /**
   * Score based on manufacturer
   * @param {string} manufacturer - Manufacturer name
   * @param {Object} scores - Scores object to update
   */
  _scoreByManufacturer(manufacturer, scores) {
    const lower = manufacturer.toLowerCase();

    for (const [type, patterns] of Object.entries(this.manufacturerPatterns)) {
      for (const pattern of patterns) {
        if (lower.includes(pattern)) {
          scores[type] += 5;
        }
      }
    }
  }

  /**
   * Score based on hostname
   * @param {string} hostname - Hostname
   * @param {Object} scores - Scores object to update
   */
  _scoreByHostname(hostname, scores) {
    for (const [type, pattern] of Object.entries(this.hostnamePatterns)) {
      if (pattern.test(hostname)) {
        scores[type] += 4;
      }
    }
  }

  /**
   * Score based on open ports
   * @param {Array<number>} ports - Array of open ports
   * @param {Object} scores - Scores object to update
   */
  _scoreByPorts(ports, scores) {
    for (const [type, indicatorPorts] of Object.entries(this.portIndicators)) {
      const matchCount = indicatorPorts.filter((p) => ports.includes(p)).length;
      scores[type] += matchCount * 2;
    }

    // Specific port combinations
    if (ports.includes(80) || ports.includes(443)) {
      scores[UsageTypes.SERVER] += 2;
    }

    if (ports.includes(22) && !ports.includes(3389)) {
      scores[UsageTypes.SERVER] += 1;
      scores[UsageTypes.IOT] += 1;
    }

    if (ports.includes(3389) || ports.includes(445)) {
      scores[UsageTypes.COMPUTER] += 3;
    }

    if (ports.includes(5353)) {
      // mDNS - Apple device
      scores[UsageTypes.COMPUTER] += 1;
      scores[UsageTypes.MOBILE] += 1;
    }
  }

  /**
   * Score based on operating system
   * @param {string} os - Operating system
   * @param {Object} scores - Scores object to update
   */
  _scoreByOS(os, scores) {
    const lower = os.toLowerCase();

    if (lower.includes('ios') || lower.includes('iphone') || lower.includes('ipad')) {
      scores[UsageTypes.MOBILE] += 6;
    } else if (lower.includes('android')) {
      scores[UsageTypes.MOBILE] += 6;
    } else if (lower.includes('windows')) {
      scores[UsageTypes.COMPUTER] += 4;
    } else if (lower.includes('mac') || lower.includes('darwin')) {
      scores[UsageTypes.COMPUTER] += 4;
    } else if (
      lower.includes('linux') ||
      lower.includes('ubuntu') ||
      lower.includes('debian')
    ) {
      scores[UsageTypes.SERVER] += 3;
      scores[UsageTypes.IOT] += 2;
    } else if (lower.includes('openwrt') || lower.includes('dd-wrt')) {
      scores[UsageTypes.ROUTER] += 5;
    } else if (lower.includes('embedded')) {
      scores[UsageTypes.IOT] += 4;
    }
  }

  /**
   * Get detailed analysis of device type
   * @param {Object} device - Device data
   * @returns {Object} Detailed analysis
   */
  analyze(device) {
    const inference = this.infer(device);

    return {
      ...inference,
      details: {
        manufacturer: device.manufacturer || 'Unknown',
        os: device.os || 'Unknown',
        hostname: device.hostname || 'Unknown',
        openPorts: device.ports?.length || 0,
        hasPrinterPorts: device.ports?.some((p) => [631, 9100, 515].includes(p)),
        hasServerPorts: device.ports?.some((p) => [80, 443, 22].includes(p)),
        hasWindowsPorts: device.ports?.some((p) => [3389, 445].includes(p)),
      },
    };
  }

  /**
   * Check if device is likely a specific type
   * @param {Object} device - Device data
   * @param {string} type - Usage type to check
   * @returns {boolean} True if device is likely this type
   */
  isType(device, type) {
    const inference = this.infer(device);
    return inference.usage === type && inference.confidence > 50;
  }

  /**
   * Get all possible types with their confidence scores
   * @param {Object} device - Device data
   * @returns {Array<Object>} Array of types with confidence scores
   */
  getPossibleTypes(device) {
    const inference = this.infer(device);

    return Object.entries(inference.scores)
      .filter(([, score]) => score > 0)
      .map(([type, score]) => ({
        type,
        confidence: Math.min((score / 10) * 100, 100),
      }))
      .sort((a, b) => b.confidence - a.confidence);
  }
}

// Export singleton instance
export const usageInferrer = new UsageInferrer();
