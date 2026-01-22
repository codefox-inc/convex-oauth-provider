import type {
    FunctionReference,
    FunctionVisibility,
    FunctionArgs,
    FunctionReturnType,
} from "convex/server";

/**
 * Convex component common Context types
 *
 * Unified RunQueryCtx, RunMutationCtx, RunActionCtx that were defined separately in each package.
 *
 * Using generics, infer return value types from FunctionReference.
 * - FunctionVisibility: supports both internal/public functions
 * - FunctionArgs<F>: extracts function argument types
 * - FunctionReturnType<F>: extracts function return value types
 */
export type RunQueryCtx = {
    runQuery<F extends FunctionReference<"query", FunctionVisibility>>(
        query: F,
        args: FunctionArgs<F>,
    ): Promise<FunctionReturnType<F>>;
};

export type RunMutationCtx = RunQueryCtx & {
    runMutation<F extends FunctionReference<"mutation", FunctionVisibility>>(
        mutation: F,
        args: FunctionArgs<F>,
    ): Promise<FunctionReturnType<F>>;
};

export type RunActionCtx = RunMutationCtx & {
    runAction<F extends FunctionReference<"action", FunctionVisibility>>(
        action: F,
        args: FunctionArgs<F>,
    ): Promise<FunctionReturnType<F>>;
};
