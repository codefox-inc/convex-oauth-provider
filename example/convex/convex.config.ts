import { defineApp } from "convex/server";
import oauthProvider from "@codefox-inc/oauth-provider/convex.config.js";

const app = defineApp();
app.use(oauthProvider);

export default app;
