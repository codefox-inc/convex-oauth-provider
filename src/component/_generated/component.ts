/* eslint-disable */
/**
 * Generated `ComponentApi` utility.
 *
 * THIS CODE IS AUTOMATICALLY GENERATED.
 *
 * To regenerate, run `npx convex dev`.
 * @module
 */

import type { FunctionReference } from "convex/server";

/**
 * A utility for referencing a Convex component's exposed API.
 *
 * Useful when expecting a parameter like `components.myComponent`.
 * Usage:
 * ```ts
 * async function myFunction(ctx: QueryCtx, component: ComponentApi) {
 *   return ctx.runQuery(component.someFile.someQuery, { ...args });
 * }
 * ```
 */
export type ComponentApi<Name extends string | undefined = string | undefined> =
  {
    clientManagement: {
      deleteClient: FunctionReference<
        "mutation",
        "internal",
        { clientId: string },
        any,
        Name
      >;
      registerClient: FunctionReference<
        "mutation",
        "internal",
        {
          description?: string;
          isInternal?: boolean;
          logoUrl?: string;
          name: string;
          policyUrl?: string;
          redirectUris: Array<string>;
          scopes: Array<string>;
          tosUrl?: string;
          type: "confidential" | "public";
          website?: string;
        },
        any,
        Name
      >;
      verifyClientSecret: FunctionReference<
        "mutation",
        "internal",
        { clientId: string; clientSecret: string },
        any,
        Name
      >;
    };
    mutations: {
      consumeAuthCode: FunctionReference<
        "mutation",
        "internal",
        {
          clientId: string;
          code: string;
          codeVerifier: string;
          redirectUri?: string;
        },
        any,
        Name
      >;
      deleteClient: FunctionReference<
        "mutation",
        "internal",
        { clientId: string },
        any,
        Name
      >;
      issueAuthorizationCode: FunctionReference<
        "mutation",
        "internal",
        {
          clientId: string;
          codeChallenge: string;
          codeChallengeMethod: string;
          nonce?: string;
          redirectUri: string;
          scopes: Array<string>;
          userId: string;
        },
        any,
        Name
      >;
      revokeAuthorization: FunctionReference<
        "mutation",
        "internal",
        { clientId: string; userId: string },
        any,
        Name
      >;
      rotateRefreshToken: FunctionReference<
        "mutation",
        "internal",
        {
          accessToken: string;
          clientId: string;
          expiresAt: number;
          oldRefreshToken: string;
          refreshToken?: string;
          refreshTokenExpiresAt?: number;
          scopes: Array<string>;
          userId: string;
        },
        any,
        Name
      >;
      saveTokens: FunctionReference<
        "mutation",
        "internal",
        {
          accessToken: string;
          authorizationCode?: string;
          clientId: string;
          expiresAt: number;
          refreshToken?: string;
          refreshTokenExpiresAt?: number;
          scopes: Array<string>;
          userId: string;
        },
        any,
        Name
      >;
      updateAuthorizationLastUsed: FunctionReference<
        "mutation",
        "internal",
        { clientId: string; userId: string },
        any,
        Name
      >;
      upsertAuthorization: FunctionReference<
        "mutation",
        "internal",
        { clientId: string; scopes: Array<string>; userId: string },
        any,
        Name
      >;
    };
    queries: {
      getAuthorization: FunctionReference<
        "query",
        "internal",
        { clientId: string; userId: string },
        any,
        Name
      >;
      getClient: FunctionReference<
        "query",
        "internal",
        { clientId: string },
        any,
        Name
      >;
      getRefreshToken: FunctionReference<
        "query",
        "internal",
        { refreshToken: string },
        any,
        Name
      >;
      getTokensByUser: FunctionReference<
        "query",
        "internal",
        { userId: string },
        any,
        Name
      >;
      hasAnyAuthorization: FunctionReference<
        "query",
        "internal",
        { userId: string },
        any,
        Name
      >;
      hasAuthorization: FunctionReference<
        "query",
        "internal",
        { clientId: string; userId: string },
        any,
        Name
      >;
      listClients: FunctionReference<"query", "internal", {}, any, Name>;
      listUserAuthorizations: FunctionReference<
        "query",
        "internal",
        { userId: string },
        any,
        Name
      >;
    };
  };
