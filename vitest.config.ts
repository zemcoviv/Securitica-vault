import { defineConfig } from "vitest/config";

// Security + unit tests run in Node (SubtleCrypto + WASM Argon2 available).
export default defineConfig({
  test: {
    include: ["miniapp/src/**/*.test.ts", "tests/**/*.test.ts"],
    environment: "node",
  },
});
