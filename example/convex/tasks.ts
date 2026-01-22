import { query, mutation, internalQuery, internalMutation } from "./_generated/server";
import { v } from "convex/values";
import { getAuthUserId } from "./auth";
import type { Id } from "./_generated/dataModel";
import type { QueryCtx, MutationCtx } from "./_generated/server";
import { createAuthHelper, isOAuthToken, getOAuthClientId } from "@codefox-inc/oauth-provider";

/**
 * Tasks CRUD operations
 *
 * These functions can be called:
 * 1. Directly from the frontend (using Convex Auth)
 * 2. Via MCP server (using OAuth token -> userId)
 */

// Create auth helper for unified authentication
// OAuth tokens are valid until expiration; revocation only prevents refresh
const authHelper = createAuthHelper({
  providers: ["anonymous"],
});

/**
 * Get user ID from current user
 * Supports both Convex Auth (session) and OAuth tokens (MCP)
 *
 * This demonstrates using isOAuthToken helper for OAuth token detection
 * (similar pattern to codefox-business-suite's getCurrentUser)
 */
async function getUserId(ctx: QueryCtx | MutationCtx): Promise<Id<"users"> | null> {
  // 1. Check for OAuth 2.1 token first
  const identity = await ctx.auth.getUserIdentity();
  if (identity && isOAuthToken(identity)) {
    // OAuth token: get userId from subject
    const validId = ctx.db.normalizeId("users", identity.subject!);
    if (validId) {
      // Optional: log client ID for debugging/auditing
      const clientId = getOAuthClientId(identity as { cid?: string });
      console.log(`OAuth request from client: ${clientId}`);
      return validId;
    }
    return null;
  }

  // 2. Fall back to Convex Auth (session)
  return authHelper.getCurrentUserId(ctx, getAuthUserId) as Promise<Id<"users"> | null>;
}

// ---------------------------------------------------------
// Queries
// ---------------------------------------------------------

export const list = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getUserId(ctx);
    if (!userId) {
      return [];
    }

    return await ctx.db
      .query("tasks")
      .withIndex("by_user", (q) => q.eq("userId", userId))
      .order("desc")
      .collect();
  },
});

export const get = query({
  args: { taskId: v.id("tasks") },
  handler: async (ctx, args) => {
    const userId = await getUserId(ctx);
    if (!userId) return null;

    const task = await ctx.db.get(args.taskId);
    if (!task || task.userId !== userId) return null;

    return task;
  },
});

// Internal queries for MCP (uses userId from OAuth token)
export const listByUserId = internalQuery({
  args: { userId: v.id("users") },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("tasks")
      .withIndex("by_user", (q) => q.eq("userId", args.userId))
      .order("desc")
      .collect();
  },
});

export const getByUserId = internalQuery({
  args: { taskId: v.id("tasks"), userId: v.id("users") },
  handler: async (ctx, args) => {
    const task = await ctx.db.get(args.taskId);
    if (!task || task.userId !== args.userId) return null;
    return task;
  },
});

// ---------------------------------------------------------
// Mutations
// ---------------------------------------------------------

export const create = mutation({
  args: {
    title: v.string(),
    description: v.optional(v.string()),
    priority: v.optional(v.union(v.literal("low"), v.literal("medium"), v.literal("high"))),
    dueDate: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const userId = await getUserId(ctx);
    if (!userId) {
      throw new Error("Not authenticated");
    }

    const now = Date.now();
    return await ctx.db.insert("tasks", {
      userId,
      title: args.title,
      description: args.description,
      status: "pending",
      priority: args.priority,
      dueDate: args.dueDate,
      createdAt: now,
      updatedAt: now,
    });
  },
});

export const update = mutation({
  args: {
    taskId: v.id("tasks"),
    title: v.optional(v.string()),
    description: v.optional(v.string()),
    status: v.optional(v.union(v.literal("pending"), v.literal("in_progress"), v.literal("done"))),
    priority: v.optional(v.union(v.literal("low"), v.literal("medium"), v.literal("high"))),
    dueDate: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const userId = await getUserId(ctx);
    if (!userId) {
      throw new Error("Not authenticated");
    }

    const task = await ctx.db.get(args.taskId);
    if (!task || task.userId !== userId) {
      throw new Error("Task not found or not authorized");
    }

    const { taskId, ...updates } = args;
    await ctx.db.patch(taskId, {
      ...updates,
      updatedAt: Date.now(),
    });
  },
});

export const remove = mutation({
  args: { taskId: v.id("tasks") },
  handler: async (ctx, args) => {
    const userId = await getUserId(ctx);
    if (!userId) {
      throw new Error("Not authenticated");
    }

    const task = await ctx.db.get(args.taskId);
    if (!task || task.userId !== userId) {
      throw new Error("Task not found or not authorized");
    }

    await ctx.db.delete(args.taskId);
  },
});

// Internal mutations for MCP (uses userId from OAuth token)
export const createByUserId = internalMutation({
  args: {
    userId: v.id("users"),
    title: v.string(),
    description: v.optional(v.string()),
    priority: v.optional(v.union(v.literal("low"), v.literal("medium"), v.literal("high"))),
    dueDate: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const now = Date.now();
    return await ctx.db.insert("tasks", {
      userId: args.userId,
      title: args.title,
      description: args.description,
      status: "pending",
      priority: args.priority,
      dueDate: args.dueDate,
      createdAt: now,
      updatedAt: now,
    });
  },
});

export const updateByUserId = internalMutation({
  args: {
    userId: v.id("users"),
    taskId: v.id("tasks"),
    title: v.optional(v.string()),
    description: v.optional(v.string()),
    status: v.optional(v.union(v.literal("pending"), v.literal("in_progress"), v.literal("done"))),
    priority: v.optional(v.union(v.literal("low"), v.literal("medium"), v.literal("high"))),
    dueDate: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const task = await ctx.db.get(args.taskId);
    if (!task || task.userId !== args.userId) {
      throw new Error("Task not found or not authorized");
    }

    const { userId: _userId, taskId, ...updates } = args;
    await ctx.db.patch(taskId, {
      ...updates,
      updatedAt: Date.now(),
    });
  },
});

export const removeByUserId = internalMutation({
  args: {
    userId: v.id("users"),
    taskId: v.id("tasks"),
  },
  handler: async (ctx, args) => {
    const task = await ctx.db.get(args.taskId);
    if (!task || task.userId !== args.userId) {
      throw new Error("Task not found or not authorized");
    }

    await ctx.db.delete(args.taskId);
  },
});
