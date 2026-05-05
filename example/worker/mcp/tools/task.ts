import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { z } from 'zod'
import type { ConvexClient } from 'convex/browser'
import { internal } from '../../../convex/_generated/api'
import { createJsonResponse, createTextResponse, createErrorResponse } from '../helpers'

const statusEnum = z.enum(['pending', 'in_progress', 'done']);
const priorityEnum = z.enum(['low', 'medium', 'high']);

export function registerTaskTools(server: McpServer, convex: ConvexClient, userId: string) {
  // List tasks
  server.tool(
    'task-list',
    'Get list of tasks for the authenticated user',
    {},
    async () => {
      try {
        const tasks = await convex.query(internal.tasks.listByUserId as any, {
          userId: userId as any,
        });
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
        const task = await convex.query(internal.tasks.getByUserId as any, {
          taskId: taskId as any,
          userId: userId as any,
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
        const taskId = await convex.mutation(internal.tasks.createByUserId as any, {
          userId: userId as any,
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
        await convex.mutation(internal.tasks.updateByUserId as any, {
          userId: userId as any,
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
        await convex.mutation(internal.tasks.removeByUserId as any, {
          userId: userId as any,
          taskId: taskId as any,
        });
        return createTextResponse(`Task deleted. ID: ${taskId}`);
      } catch (error) {
        return createErrorResponse(error);
      }
    }
  );
}
