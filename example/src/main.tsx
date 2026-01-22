import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ConvexReactClient } from "convex/react";
import { ConvexAuthProvider } from "@convex-dev/auth/react";
import App from "./App";
import { OAuthConsent } from "./OAuthConsent";
import "./index.css";

const address = import.meta.env.VITE_CONVEX_URL;

const convex = new ConvexReactClient(address);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ConvexAuthProvider client={convex}>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<App />} />
          <Route path="/oauth/authorize" element={<OAuthConsent />} />
        </Routes>
      </BrowserRouter>
    </ConvexAuthProvider>
  </StrictMode>
);
