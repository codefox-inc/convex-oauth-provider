import { generateAuthConfig } from "@codefox-inc/oauth-provider";

export default generateAuthConfig({
  convexSiteUrl: process.env.CONVEX_SITE_URL,
  localPort: 5173,
});
