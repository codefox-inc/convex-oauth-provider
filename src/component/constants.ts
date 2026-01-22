/**
 * OAuth 2.1 Provider Constants
 */
export const OAUTH_CONSTANTS = {
    // Code & Token Expiry
    CODE_EXPIRY_MS: 10 * 60 * 1000,              // 10 minutes
    ACCESS_TOKEN_EXPIRY_SECONDS: 3600,           // 1 hour
    ACCESS_TOKEN_EXPIRY: "1h",
    ID_TOKEN_EXPIRY: "1h",
    REFRESH_TOKEN_EXPIRY_MS: 30 * 24 * 60 * 60 * 1000, // 30 days

    // Code Generation
    AUTH_CODE_LENGTH: 32,
    CLIENT_SECRET_LENGTH: 64,

    // Supported Values
    SUPPORTED_SCOPES: ["openid", "profile", "email", "offline_access"],
    SUPPORTED_GRANT_TYPES: ["authorization_code", "refresh_token"],
    SUPPORTED_RESPONSE_TYPES: ["code"],
    SUPPORTED_CODE_CHALLENGE_METHODS: ["S256"],

    // Keys
    DEFAULT_KEY_ID: "default-key",

    // CORS
    CORS_MAX_AGE: "3600", // 1 hour
} as const;

/**
 * OAuth Error Codes (RFC 6749)
 */
export const OAUTH_ERROR_CODES = {
    INVALID_REQUEST: "invalid_request",
    INVALID_CLIENT: "invalid_client",
    INVALID_GRANT: "invalid_grant",
    UNAUTHORIZED_CLIENT: "unauthorized_client",
    UNSUPPORTED_GRANT_TYPE: "unsupported_grant_type",
    INVALID_SCOPE: "invalid_scope",
    SERVER_ERROR: "server_error",
} as const;
