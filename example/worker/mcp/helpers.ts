/**
 * MCP Server helper functions
 */

/**
 * Create error response for MCP tools
 */
export function createErrorResponse(error: unknown) {
  const message = error instanceof Error ? error.message : 'Unknown error';
  return {
    content: [{ type: 'text' as const, text: `Error: ${message}` }],
    isError: true,
  };
}

/**
 * Create success response (text)
 */
export function createTextResponse(text: string) {
  return {
    content: [{ type: 'text' as const, text }],
  };
}

/**
 * Create success response (JSON)
 */
export function createJsonResponse(data: unknown) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }],
  };
}
