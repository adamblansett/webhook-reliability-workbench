import dns from 'node:dns';
import dnsPromises from 'node:dns/promises';
import net from 'node:net';

export class SsrSecurityError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
    public readonly destination?: string,
  ) {
    super(message);
    this.name = 'SsrSecurityError';
  }
}

export interface SsrValidationOptions {
  /** Explicitly allow loopback destinations (127.0.0.1, localhost, ::1) */
  allowLoopback?: boolean;
  /** Explicitly allow private network destinations (10.0.0.0/8, 192.168.0.0/16, etc.) */
  allowPrivate?: boolean;
  /** Explicit list of allowed destination URLs or hostname prefixes */
  allowedDestinations?: string[];
}

export interface ValidatedDestination {
  url: URL;
  resolvedIps: string[];
  isLoopback: boolean;
  isPrivate: boolean;
}

/**
 * Checks if an IPv4 address falls within a given CIDR block.
 */
function isIpv4InCidr(ip: string, cidrBase: string, prefixLength: number): boolean {
  const ipParts = ip.split('.').map(Number);
  const baseParts = cidrBase.split('.').map(Number);

  if (ipParts.length !== 4 || baseParts.length !== 4) {
    return false;
  }

  const ipInt =
    ((ipParts[0]! << 24) | (ipParts[1]! << 16) | (ipParts[2]! << 8) | ipParts[3]!) >>> 0;
  const baseInt =
    ((baseParts[0]! << 24) |
      (baseParts[1]! << 16) |
      (baseParts[2]! << 8) |
      baseParts[3]!) >>>
    0;

  const mask = prefixLength === 0 ? 0 : (~0 << (32 - prefixLength)) >>> 0;
  return (ipInt & mask) === (baseInt & mask);
}

/**
 * Normalizes an IPv6 address that wraps an IPv4 address (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1).
 */
export function normalizeIp(ip: string): string {
  let clean = ip.trim();
  if (clean.startsWith('[') && clean.endsWith(']')) {
    clean = clean.slice(1, -1);
  }

  const lower = clean.toLowerCase();
  if (lower.startsWith('::ffff:') || lower.startsWith('0:0:0:0:0:ffff:')) {
    const candidate = lower.startsWith('::ffff:') ? lower.slice(7) : lower.slice(15);
    if (net.isIPv4(candidate)) {
      return candidate;
    }

    // Handle hex-encoded IPv4-mapped IPv6 (e.g., 7f00:1, 7f00:0001, a9fe:a9fe)
    if (candidate.includes(':')) {
      const parts = candidate.split(':');
      if (parts.length === 2) {
        const high = parseInt(parts[0]!, 16);
        const low = parseInt(parts[1]!, 16);
        if (
          !isNaN(high) &&
          !isNaN(low) &&
          high >= 0 &&
          high <= 0xffff &&
          low >= 0 &&
          low <= 0xffff
        ) {
          const b1 = (high >> 8) & 0xff;
          const b2 = high & 0xff;
          const b3 = (low >> 8) & 0xff;
          const b4 = low & 0xff;
          return `${b1}.${b2}.${b3}.${b4}`;
        }
      }
    }
  }

  return lower;
}

/**
 * Checks if an IP is a loopback address.
 */
export function isLoopbackIp(ip: string): boolean {
  const norm = normalizeIp(ip);
  if (net.isIPv4(norm)) {
    return isIpv4InCidr(norm, '127.0.0.0', 8);
  }
  return norm === '::1' || norm === '0:0:0:0:0:0:0:1';
}

/**
 * Checks if an IP address is a private/internal IP address.
 */
export function isPrivateIp(ip: string): boolean {
  const norm = normalizeIp(ip);

  if (net.isIPv4(norm)) {
    return (
      isIpv4InCidr(norm, '10.0.0.0', 8) ||
      isIpv4InCidr(norm, '172.16.0.0', 12) ||
      isIpv4InCidr(norm, '192.168.0.0', 16)
    );
  }

  // IPv6 unique local (fc00::/7) or site-local (fec0::/10)
  return norm.startsWith('fc') || norm.startsWith('fd') || norm.startsWith('fe80');
}

/**
 * Checks if an IP is a link-local address or cloud metadata endpoint.
 */
export function isLinkLocalOrMetadataIp(ip: string): boolean {
  const norm = normalizeIp(ip);

  if (norm === '169.254.169.254') {
    return true;
  }

  if (net.isIPv4(norm)) {
    return isIpv4InCidr(norm, '169.254.0.0', 16);
  }

  return norm.startsWith('fe80:');
}

/**
 * Checks if an IP is multicast, broadcast, or reserved special address.
 */
export function isSpecialOrRestrictedIp(ip: string): boolean {
  const norm = normalizeIp(ip);

  if (net.isIPv4(norm)) {
    return (
      isIpv4InCidr(norm, '0.0.0.0', 8) || // current network
      isIpv4InCidr(norm, '100.64.0.0', 10) || // Shared Address Space / CGN
      isIpv4InCidr(norm, '192.0.0.0', 24) || // IETF Protocol Assignments
      isIpv4InCidr(norm, '198.18.0.0', 15) || // Benchmarking
      isIpv4InCidr(norm, '224.0.0.0', 4) || // Multicast
      isIpv4InCidr(norm, '240.0.0.0', 4) || // Reserved for future use
      norm === '255.255.255.255'
    );
  }

  return (
    norm === '::' ||
    norm.startsWith('ff') || // IPv6 Multicast
    norm.startsWith('2001:db8:') // Documentation
  );
}

const BLOCKED_HOSTNAMES = new Set([
  'metadata.google.internal',
  'instance-data',
  '169.254.169.254',
  'metadata',
]);

/**
 * Validates a replay destination URL against SSRF rules and resolves DNS.
 * Throws SsrSecurityError if safety requirements are violated.
 */
export async function validateDestinationUrl(
  destinationUrl: string,
  options: SsrValidationOptions = {},
): Promise<ValidatedDestination> {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(destinationUrl);
  } catch {
    throw new SsrSecurityError(
      `Invalid URL format: "${destinationUrl}"`,
      'INVALID_URL_FORMAT',
      destinationUrl,
    );
  }

  // Scheme validation: strictly http or https
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new SsrSecurityError(
      `Unsupported protocol scheme "${parsedUrl.protocol}". Only "http:" and "https:" are permitted.`,
      'UNSUPPORTED_PROTOCOL',
      destinationUrl,
    );
  }

  // Reject embedded credentials
  if (parsedUrl.username || parsedUrl.password) {
    throw new SsrSecurityError(
      'URLs with embedded username or password credentials are forbidden.',
      'EMBEDDED_CREDENTIALS',
      destinationUrl,
    );
  }

  let hostname = parsedUrl.hostname.toLowerCase();
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    hostname = hostname.slice(1, -1);
  }

  // Reject empty or special blocked hostnames
  if (!hostname) {
    throw new SsrSecurityError(
      'URL must specify a valid hostname.',
      'MISSING_HOSTNAME',
      destinationUrl,
    );
  }

  if (BLOCKED_HOSTNAMES.has(hostname)) {
    throw new SsrSecurityError(
      `Access to cloud metadata hostname "${hostname}" is strictly blocked.`,
      'METADATA_HOSTNAME_BLOCKED',
      destinationUrl,
    );
  }

  // Check explicit destination allowlist if configured
  if (options.allowedDestinations && options.allowedDestinations.length > 0) {
    const isAllowed = options.allowedDestinations.some((allowed) => {
      try {
        const allowedUrl = new URL(allowed);
        return (
          allowedUrl.origin === parsedUrl.origin &&
          parsedUrl.pathname.startsWith(allowedUrl.pathname)
        );
      } catch {
        return destinationUrl.startsWith(allowed) || hostname === allowed;
      }
    });

    if (isAllowed) {
      return {
        url: parsedUrl,
        resolvedIps: [],
        isLoopback: false,
        isPrivate: false,
      };
    }
  }

  const isLocalhostHost = hostname === 'localhost' || hostname.endsWith('.localhost');

  // Resolve hostname to IP addresses
  const resolvedIps: string[] = [];
  if (net.isIP(hostname)) {
    resolvedIps.push(hostname);
  } else {
    try {
      const records = await dnsPromises.lookup(hostname, { all: true });
      for (const record of records) {
        resolvedIps.push(record.address);
      }
    } catch (err) {
      if (isLocalhostHost) {
        resolvedIps.push('127.0.0.1');
      } else {
        throw new SsrSecurityError(
          `Failed to resolve hostname "${hostname}": ${err instanceof Error ? err.message : String(err)}`,
          'DNS_RESOLUTION_FAILED',
          destinationUrl,
        );
      }
    }
  }

  if (resolvedIps.length === 0) {
    throw new SsrSecurityError(
      `No IP addresses resolved for hostname "${hostname}".`,
      'DNS_RESOLUTION_EMPTY',
      destinationUrl,
    );
  }

  let hasLoopback = false;
  let hasPrivate = false;

  for (const rawIp of resolvedIps) {
    const check = assertIpAllowed(rawIp, destinationUrl, options, isLocalhostHost);
    if (check.isLoopback) hasLoopback = true;
    if (check.isPrivate) hasPrivate = true;
  }

  return {
    url: parsedUrl,
    resolvedIps,
    isLoopback: hasLoopback,
    isPrivate: hasPrivate,
  };
}

/**
 * Validates a single IP address against SSRF rules.
 */
export function assertIpAllowed(
  rawIp: string,
  destinationUrl: string,
  options: SsrValidationOptions = {},
  isLocalhostHost = false,
): { isLoopback: boolean; isPrivate: boolean } {
  const ip = normalizeIp(rawIp);

  // Link-local / Cloud metadata
  if (isLinkLocalOrMetadataIp(ip)) {
    throw new SsrSecurityError(
      `Destination resolves to link-local or metadata IP "${ip}", which is strictly prohibited.`,
      'LINK_LOCAL_METADATA_BLOCKED',
      destinationUrl,
    );
  }

  // Special or restricted IP (e.g. 0.0.0.0, broadcast, multicast)
  if (isSpecialOrRestrictedIp(ip)) {
    throw new SsrSecurityError(
      `Destination resolves to restricted IP "${ip}".`,
      'RESTRICTED_IP_BLOCKED',
      destinationUrl,
    );
  }

  let isLoopback = false;
  let isPrivate = false;

  // Loopback checks
  if (isLoopbackIp(ip) || isLocalhostHost) {
    isLoopback = true;
    if (!options.allowLoopback) {
      throw new SsrSecurityError(
        `Destination "${destinationUrl}" resolves to loopback IP "${ip}". Replaying to loopback requires explicit opt-in (--allow-loopback).`,
        'LOOPBACK_BLOCKED',
        destinationUrl,
      );
    }
  }

  // Private network checks
  if (isPrivateIp(ip)) {
    isPrivate = true;
    if (!options.allowPrivate) {
      throw new SsrSecurityError(
        `Destination "${destinationUrl}" resolves to private network IP "${ip}". Replaying to private IPs requires explicit opt-in (--allow-private).`,
        'PRIVATE_IP_BLOCKED',
        destinationUrl,
      );
    }
  }

  return { isLoopback, isPrivate };
}

/**
 * Creates a custom DNS lookup function that validates resolved IP addresses
 * against SSRF policies at connection time, eliminating DNS rebinding gaps.
 */
export function createSsrfLookup(options: SsrValidationOptions = {}): net.LookupFunction {
  return (
    hostname: string,
    lookupOpts: dns.LookupOptions,
    callback: (
      err: NodeJS.ErrnoException | null,
      address: string | dns.LookupAddress[],
      family?: number,
    ) => void,
  ) => {
    let cleanHost = hostname.toLowerCase();
    if (cleanHost.startsWith('[') && cleanHost.endsWith(']')) {
      cleanHost = cleanHost.slice(1, -1);
    }

    if (BLOCKED_HOSTNAMES.has(cleanHost)) {
      const err = new SsrSecurityError(
        `Access to cloud metadata hostname "${cleanHost}" is strictly blocked.`,
        'METADATA_HOSTNAME_BLOCKED',
        hostname,
      );
      return callback(err as unknown as NodeJS.ErrnoException, '');
    }

    const isLocalhostHost = cleanHost === 'localhost' || cleanHost.endsWith('.localhost');

    // If already an IP address
    if (net.isIP(cleanHost)) {
      try {
        assertIpAllowed(cleanHost, hostname, options, isLocalhostHost);
        const family = net.isIP(cleanHost);
        if (lookupOpts && lookupOpts.all) {
          return callback(null, [{ address: cleanHost, family }]);
        }
        return callback(null, cleanHost, family);
      } catch (validationErr) {
        return callback(validationErr as unknown as NodeJS.ErrnoException, '');
      }
    }

    // Resolve DNS and check every address
    dns.lookup(
      cleanHost,
      { all: true },
      (dnsErr: NodeJS.ErrnoException | null, addresses: dns.LookupAddress[]) => {
        if (dnsErr) {
          if (isLocalhostHost) {
            try {
              assertIpAllowed('127.0.0.1', hostname, options, true);
              if (lookupOpts && lookupOpts.all) {
                return callback(null, [{ address: '127.0.0.1', family: 4 }]);
              }
              return callback(null, '127.0.0.1', 4);
            } catch (valErr) {
              return callback(valErr as unknown as NodeJS.ErrnoException, '');
            }
          }
          return callback(dnsErr, '');
        }

        if (!addresses || addresses.length === 0) {
          const emptyErr = new SsrSecurityError(
            `No IP addresses resolved for hostname "${cleanHost}".`,
            'DNS_RESOLUTION_EMPTY',
            hostname,
          );
          return callback(emptyErr as unknown as NodeJS.ErrnoException, '');
        }

        try {
          for (const record of addresses) {
            assertIpAllowed(record.address, hostname, options, isLocalhostHost);
          }

          if (lookupOpts && lookupOpts.all) {
            return callback(null, addresses);
          }
          return callback(null, addresses[0]!.address, addresses[0]!.family);
        } catch (valErr) {
          return callback(valErr as unknown as NodeJS.ErrnoException, '');
        }
      },
    );
  };
}
