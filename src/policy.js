import { isIP } from 'node:net';

export function normalizeTarget(value) {
  if (typeof value !== 'string' || value.length > 2048) throw new Error('Enter an HTTPS URL, up to 2,048 characters.');
  let parsed;
  try { parsed = new URL(value.trim()); } catch { throw new Error('Enter a complete HTTPS URL, such as https://your-client.com.'); }
  const host = parsed.hostname.toLowerCase().replace(/\.$/, '');
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || (parsed.port && parsed.port !== '443')) throw new Error('Only HTTPS URLs without credentials or custom ports are supported.');
  if (host.length > 253 || !/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(host) || /(?:^|\.)(?:localhost|local|internal|home|lan|test|invalid|example|onion)$/.test(host)) throw new Error('Use a public website hostname. IP addresses and private networks are not supported.');
  parsed.hostname = host;
  parsed.hash = '';
  return parsed.href;
}

function ipv6Number(address) {
  // WHATWG canonicalization converts embedded IPv4 to hextets. net.isIP has
  // already checked syntax, including zone identifiers (rejected below).
  const canonical = new URL(`https://[${address}]/`).hostname.slice(1, -1);
  const halves = canonical.split('::');
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const groups = halves.length === 2 ? [...left, ...Array(8 - left.length - right.length).fill('0'), ...right] : left;
  return groups.reduce((n, h) => (n << 16n) | BigInt(`0x${h}`), 0n);
}
function inPrefix(value, prefix, bits) {
  const shift = 128n - BigInt(bits);
  return (value >> shift) === (ipv6Number(prefix) >> shift);
}

export function isPublicAddress(address) {
  if (typeof address !== 'string' || address.includes('%')) return false;
  const family = isIP(address);
  if (family === 4) {
    const [a, b, c] = address.split('.').map(Number);
    // Conservatively reject special-purpose ranges, including private,
    // loopback, link-local/cloud metadata, CGNAT, documentation and multicast.
    return !(a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113) || address === '168.63.129.16');
  }
  if (family !== 6) return false;
  try {
    const value = ipv6Number(address);
    // Only global-unicast 2000::/3. Exclude special assignments, docs and
    // transition ranges; mapped IPv4, NAT64, ULA and link-local fail closed.
    return inPrefix(value, '2000::', 3) &&
      !inPrefix(value, '2001::', 23) && !inPrefix(value, '2001:db8::', 32) &&
      !inPrefix(value, '2002::', 16) && !inPrefix(value, '3fff::', 20);
  } catch { return false; }
}
