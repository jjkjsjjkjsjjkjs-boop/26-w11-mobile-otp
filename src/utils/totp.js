/**
 * TOTP (RFC 6238) & HOTP (RFC 4226) implementation using Web Crypto API
 * Zero-Transmission: 100% client-side cryptographic operations
 */

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

const getCrypto = () => {
  if (typeof window !== 'undefined' && window.crypto) return window.crypto;
  if (typeof globalThis !== 'undefined' && globalThis.crypto) return globalThis.crypto;
  throw new Error('Web Crypto API is not available');
};

/**
 * Generate a cryptographically secure Base32 secret key using crypto.getRandomValues
 * @param {number} length - Number of Base32 characters (default: 32 chars = 160 bits)
 * @returns {string} Base32 encoded secret key
 */
export function generateBase32Secret(length = 32) {
  const cryptoObj = getCrypto();
  const randomBytes = new Uint8Array(length);
  cryptoObj.getRandomValues(randomBytes);
  let secret = '';
  for (let i = 0; i < length; i++) {
    // 256 is an exact multiple of 32 (256 / 32 = 8), so no modulo bias
    secret += BASE32_ALPHABET[randomBytes[i] % 32];
  }
  return secret;
}

/**
 * Decode a Base32 string into a Uint8Array
 * @param {string} base32 - Base32 string (case-insensitive, ignores spaces and hyphens)
 * @returns {Uint8Array}
 */
export function base32ToBytes(base32) {
  const clean = base32.toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < clean.length; i++) {
    const char = clean[i];
    const val = BASE32_ALPHABET.indexOf(char);
    if (val === -1) {
      throw new Error(`Invalid Base32 character: "${char}"`);
    }
    value = (value << 5) | val;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(bytes);
}

/**
 * Convert a number/counter into an 8-byte Big-Endian buffer
 * @param {number} counter
 * @returns {Uint8Array}
 */
export function getCounterBuffer(counter) {
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  view.setUint32(0, high, false); // Big-Endian
  view.setUint32(4, low, false);  // Big-Endian
  return new Uint8Array(buffer);
}

/**
 * Compute HMAC-SHA1 using Web Crypto API (crypto.subtle)
 * @param {Uint8Array} keyBytes
 * @param {Uint8Array} messageBytes
 * @returns {Promise<Uint8Array>}
 */
export async function computeHmacSha1(keyBytes, messageBytes) {
  const cryptoSubtle = getCrypto().subtle;
  const cryptoKey = await cryptoSubtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: { name: 'SHA-1' } },
    false,
    ['sign']
  );
  const signature = await cryptoSubtle.sign('HMAC', cryptoKey, messageBytes);
  return new Uint8Array(signature);
}

/**
 * Helper to convert Uint8Array to Hex string
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Generate TOTP code and full internal cryptographic trace for inspector
 * @param {string} base32Secret
 * @param {number} [timeMs=Date.now()]
 * @param {number} [period=30]
 * @param {number} [digits=6]
 * @returns {Promise<{
 *   otp: string,
 *   counter: number,
 *   remainingSeconds: number,
 *   period: number,
 *   secretHex: string,
 *   counterHex: string,
 *   hmacHex: string,
 *   offset: number,
 *   truncatedBinaryHex: string,
 *   truncatedValue: number
 * }>}
 */
export async function generateTotpWithTrace(
  base32Secret,
  timeMs = Date.now(),
  period = 30,
  digits = 6
) {
  const keyBytes = base32ToBytes(base32Secret);
  const epochSeconds = Math.floor(timeMs / 1000);
  const counter = Math.floor(epochSeconds / period);
  const remainingSeconds = period - (epochSeconds % period);

  const counterBytes = getCounterBuffer(counter);
  const hmacBytes = await computeHmacSha1(keyBytes, counterBytes);

  // Dynamic Truncation (RFC 4226 Section 5.4)
  const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
  const truncatedValue =
    ((hmacBytes[offset] & 0x7f) << 24) |
    ((hmacBytes[offset + 1] & 0xff) << 16) |
    ((hmacBytes[offset + 2] & 0xff) << 8) |
    (hmacBytes[offset + 3] & 0xff);

  const modulo = 10 ** digits;
  const otpNumber = truncatedValue % modulo;
  const otp = String(otpNumber).padStart(digits, '0');

  const truncatedBinaryBytes = hmacBytes.slice(offset, offset + 4);

  return {
    otp,
    counter,
    epochSeconds,
    remainingSeconds,
    period,
    secretHex: bytesToHex(keyBytes),
    counterHex: bytesToHex(counterBytes),
    hmacHex: bytesToHex(hmacBytes),
    offset,
    truncatedBinaryHex: bytesToHex(truncatedBinaryBytes),
    truncatedValue,
  };
}

/**
 * Generate a standard 6-digit TOTP code
 * @param {string} base32Secret
 * @param {number} [timeMs=Date.now()]
 * @param {number} [period=30]
 * @param {number} [digits=6]
 * @returns {Promise<string>}
 */
export async function generateTotp(base32Secret, timeMs = Date.now(), period = 30, digits = 6) {
  const result = await generateTotpWithTrace(base32Secret, timeMs, period, digits);
  return result.otp;
}

/**
 * Verify a user input OTP code against secret with customizable window drift
 * @param {string} inputCode - 6-digit code entered by user
 * @param {string} base32Secret - Base32 secret key
 * @param {object} [options]
 * @param {number} [options.window=1] - Number of time steps to allow before/after (0 = exact 30s only, 1 = ±30s)
 * @param {number} [options.timeMs=Date.now()]
 * @param {number} [options.period=30]
 * @param {number} [options.digits=6]
 * @returns {Promise<{ valid: boolean, delta: number | null }>}
 */
export async function verifyTotp(
  inputCode,
  base32Secret,
  { window = 1, timeMs = Date.now(), period = 30, digits = 6 } = {}
) {
  const cleanInput = String(inputCode).trim().replace(/\s+/g, '');
  if (!cleanInput || cleanInput.length !== digits) {
    return { valid: false, delta: null };
  }

  const epochSeconds = Math.floor(timeMs / 1000);
  const currentCounter = Math.floor(epochSeconds / period);

  for (let delta = -window; delta <= window; delta++) {
    const testCounter = currentCounter + delta;
    const testTimeMs = testCounter * period * 1000;
    const expectedOtp = await generateTotp(base32Secret, testTimeMs, period, digits);
    if (cleanInput === expectedOtp) {
      return { valid: true, delta };
    }
  }

  return { valid: false, delta: null };
}

/**
 * Build an otpauth:// URI for QR code generation
 * @param {object} params
 * @param {string} params.issuer - Service provider name (e.g. 'CyberSec Portal')
 * @param {string} params.account - User account identifier (e.g. 'student@kopo.ac.kr')
 * @param {string} params.secret - Base32 secret
 * @param {number} [params.period=30]
 * @param {number} [params.digits=6]
 * @returns {string}
 */
export function buildOtpAuthUri({ issuer, account, secret, period = 30, digits = 6 }) {
  const cleanIssuer = issuer.trim() || 'CyberSec OTP';
  const cleanAccount = account.trim() || 'user';
  const cleanSecret = secret.toUpperCase().replace(/[\s-]/g, '');

  const label = `${encodeURIComponent(cleanIssuer)}:${encodeURIComponent(cleanAccount)}`;
  const params = new URLSearchParams({
    secret: cleanSecret,
    issuer: cleanIssuer,
    algorithm: 'SHA1',
    digits: String(digits),
    period: String(period),
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}
