import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// No CDNs, no remote assets: everything is bundled or served from /public (CLAUDE.md rule 8).
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  build: { target: "es2022", outDir: "dist", sourcemap: false, assetsInlineLimit: 0 },
});
