import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
    fsModuleCache: false,
    cache: false,
  },
  esbuild: { jsx: "automatic" },
});
