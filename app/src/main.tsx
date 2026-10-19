import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { applyAppearance, loadAppearance } from "./settings";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/content.css";
import "./styles/mobile.css";
import "./styles/app.css";

applyAppearance(loadAppearance());
const root = document.getElementById("app");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}
