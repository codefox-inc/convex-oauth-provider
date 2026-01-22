import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import type { ConvexClient } from 'convex/browser'
import { api } from '../../../convex/_generated/api'
import { createJsonResponse, createTextResponse, createErrorResponse } from '../helpers'

const statusEnum = z.enum(['pending', 'in_progress', 'done']);
const priorityEnum = z.enum(['low', 'medium', 'high']);

export function registerTaskTools(server: McpServer, convex: ConvexClient) {
  // List tasks
  server.tool(
    'task-list',
    'Get list of tasks for the authenticated user',
    {},
    async () => {
      try {
        const tasks = await convex.query(api.tasks.list, {});
        return createJsonResponse(tasks);
      } catch (error) {
        return createErrorResponse(error);
      }
    }
  );

  // Get task
  server.tool(
    'task-get',
    'Get task details by ID',
    {
      taskId: z.string().describe('Task ID'),
    },
    async ({ taskId }) => {
      try {
        const task = await convex.query(api.tasks.get, {
          taskId: taskId as any,
        });
        if (!task) {
          return createErrorResponse(new Error('Task not found'));
        }
        return createJsonResponse(task);
      } catch (error) {
        return createErrorResponse(error);
      }
    }
  );

  // Create task
  server.tool(
    'task-create',
    'Create a new task',
    {
      title: z.string().describe('Task title'),
      description: z.string().optional().describe('Task description'),
      priority: priorityEnum.optional().describe('Priority: low, medium, high'),
      dueDate: z.string().optional().describe('Due date (ISO 8601 format, e.g., 2025-01-31)'),
    },
    async ({ title, description, priority, dueDate }) => {
      try {
        const taskId = await convex.mutation(api.tasks.create, {
          title,
          description,
          priority,
          dueDate,
        });
        return createTextResponse(`Task created. ID: ${taskId}`);
      } catch (error) {
        return createErrorResponse(error);
      }
    }
  );

  // Update task
  server.tool(
    'task-update',
    'Update a task',
    {
      taskId: z.string().describe('Task ID'),
      title: z.string().optional().describe('Title'),
      description: z.string().optional().describe('Description'),
      status: statusEnum.optional().describe('Status: pending, in_progress, done'),
      priority: priorityEnum.optional().describe('Priority: low, medium, high'),
      dueDate: z.string().optional().describe('Due date (ISO 8601 format)'),
    },
    async ({ taskId, title, description, status, priority, dueDate }) => {
      try {
        await convex.mutation(api.tasks.update, {
          taskId: taskId as any,
          title,
          description,
          status,
          priority,
          dueDate,
        });
        return createTextResponse(`Task updated. ID: ${taskId}`);
      } catch (error) {
        return createErrorResponse(error);
      }
    }
  );

  // Delete task
  server.tool(
    'task-delete',
    'Delete a task',
    {
      taskId: z.string().describe('Task ID'),
    },
    async ({ taskId }) => {
      try {
        await convex.mutation(api.tasks.remove, {
          taskId: taskId as any,
        });
        return createTextResponse(`Task deleted. ID: ${taskId}`);
      } catch (error) {
        return createErrorResponse(error);
      }
    }
  );
}
