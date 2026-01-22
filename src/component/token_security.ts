/**
 * Token Security Utilities for OAuth Provider (Web Crypto API)
 *
 * Provides secure token hashing for database storage.
 * Tokens are hashed using SHA-256 before storage - the original token
 * value is never stored, only returned to the client during issuance.
 *
 * This is more secure than encryption because:
 * 1. Even with DB access + encryption key, tokens can't be recovered
 * 2. Token validation only requires hash comparison
 * 3. Clients already have the original token
 *
 * @see https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
 */

/**
 * Convert string to Uint8Array
 */
function stringToBytes(str: string): Uint8Array {
    return new TextEncoder().encode(str);
}

/**
 * Creates a SHA-256 hash of a token for secure storage.
 *
 * @param token - The plaintext token to hash
 * @returns Hex-encoded hash suitable for database storage and indexing
 *
 * @example
 * ```typescript
 * const accessToken = generateCode(64);
 * const accessTokenHash = await hashToken(accessToken);
 * // Store accessTokenHash in DB, return accessToken to client
 * ```
 */
export async function hashToken(token: string): Promise<string> {
    const tokenBytes = stringToBytes(token);
    const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        tokenBytes.buffer as ArrayBuffer
    );
    const hashArray = new Uint8Array(hashBuffer);
    return Array.from(hashArray)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Timing-safe string comparison to prevent timing attacks.
 * Compares two strings in constant time regardless of where they differ.
 */
function timingSafeEqual(a: string, b: string): boolean {
    if (a.length !== b.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

/**
 * Verifies a token against its stored hash.
 *
 * @param token - The plaintext token to verify
 * @param hash - The stored hash to compare against
 * @returns true if the token matches the hash
 */
export async function verifyToken(
    token: string,
    hash: string
): Promise<boolean> {
    const tokenHash = await hashToken(token);
    // Use timing-safe comparison to prevent timing attacks
    return timingSafeEqual(tokenHash, hash);
}

/**
 * Checks if a value looks like a SHA-256 hash (64 hex characters).
 * Used for backward compatibility during migration.
 *
 * @param value - The value to check
 * @returns true if the value appears to be a hash
 */
export function isHashedToken(value: string): boolean {
    return /^[a-f0-9]{64}$/.test(value);
}

/**
 * Hash a token if it's not already hashed.
 * Used for backward compatibility during migration.
 *
 * @param token - Token that may or may not be hashed
 * @returns The hash (either computed or passed through if already hashed)
 */
export async function ensureHashed(token: string): Promise<string> {
    if (isHashedToken(token)) {
        return token;
    }
    return hashToken(token);
}
