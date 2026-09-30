import { defineConfig } from "vitest/config";
import path from "node:path";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx", "scripts/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // page.tsx and its test use JSX without importing React (Next.js's own
  // build uses the automatic runtime via swc); tell esbuild to do the same
  // here so vitest doesn't require `React` in scope.
  esbuild: {
    jsx: "automatic",
  },
});
