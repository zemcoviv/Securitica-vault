import { defineConfig } from "vite";

// The Mini App lives in ./miniapp and is served as static assets from our own
// domain (supply-chain surface — see BRIEF §9). Crypto + plaintext never leave
// the WebView, so there is no proxy/backend bundling here.
export default defineConfig({
  root: "miniapp",
  publicDir: "public",
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    target: "es2022",
    sourcemap: false,
    // Single entry keeps the SRI/CSP surface small and auditable.
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name].[hash].js",
        chunkFileNames: "assets/[name].[hash].js",
        assetFileNames: "assets/[name].[hash][extname]",
      },
    },
  },
});
