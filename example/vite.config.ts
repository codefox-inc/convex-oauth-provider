import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  envDir: "../",
  plugins: [react()],
  resolve: {
    conditions: ["@convex-dev/component-source"],
  },
  server: {
    proxy: {
      // Proxy /mcp to the worker (including /.well-known for MCP discovery)
      "/mcp": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
      // Proxy /.well-known/* to the worker
      "/.well-known/oauth-authorization-server": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
      "/.well-known/oauth-protected-resource": {
        target: "http://localhost:8787",
        changeOrigin: true,
      },
    },
  },
});
