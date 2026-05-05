import { describe, expect, test, vi } from 'vitest'
import { internal } from '../../../convex/_generated/api'
import { registerTaskTools } from './task'

type RegisteredTool = {
  name: string
  handler: (args: any) => Promise<unknown>
}

function setupTools() {
  const tools: RegisteredTool[] = []
  const server = {
    tool: vi.fn((name: string, _description: string, _schema: unknown, handler: RegisteredTool['handler']) => {
      tools.push({ name, handler })
    }),
  }
  const convex = {
    query: vi.fn(async () => []),
    mutation: vi.fn(async () => 'task-id'),
  }

  registerTaskTools(server as any, convex as any, 'user123' as any)

  return { tools, convex }
}

describe('registerTaskTools', () => {
  test('uses internal task APIs scoped to the verified MCP user id', async () => {
    const { tools, convex } = setupTools()

    await tools.find((tool) => tool.name === 'task-list')?.handler({})
    await tools.find((tool) => tool.name === 'task-create')?.handler({
      title: 'Write tests',
      description: 'Keep user context',
      priority: 'high',
    })
    await tools.find((tool) => tool.name === 'task-update')?.handler({
      taskId: 'task123',
      status: 'done',
    })
    await tools.find((tool) => tool.name === 'task-delete')?.handler({
      taskId: 'task123',
    })

    expect(convex.query).toHaveBeenCalledWith(internal.tasks.listByUserId, {
      userId: 'user123',
    })
    expect(convex.mutation).toHaveBeenCalledWith(internal.tasks.createByUserId, {
      userId: 'user123',
      title: 'Write tests',
      description: 'Keep user context',
      priority: 'high',
      dueDate: undefined,
    })
    expect(convex.mutation).toHaveBeenCalledWith(internal.tasks.updateByUserId, {
      userId: 'user123',
      taskId: 'task123',
      title: undefined,
      description: undefined,
      status: 'done',
      priority: undefined,
      dueDate: undefined,
    })
    expect(convex.mutation).toHaveBeenCalledWith(internal.tasks.removeByUserId, {
      userId: 'user123',
      taskId: 'task123',
    })
  })
})
