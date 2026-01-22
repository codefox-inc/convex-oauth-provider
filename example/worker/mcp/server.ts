/**
 * MCP Server initialization
 */
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import type { ConvexClient } from 'convex/browser'
import { registerTaskTools } from './tools/task'

export function createMcpServer(convex: ConvexClient): McpServer {
  const server = new McpServer(
    {
      name: 'OAuth Provider Task Manager',
      version: '1.0.0',
    },
    {
      capabilities: {
        tools: {},
      },
    }
  )

  // Register task tools
  registerTaskTools(server, convex)

  return server
}
