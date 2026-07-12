import { configDefaults, defineConfig } from "vitest/config";

// Playwright owns apps/console/e2e; Vitest must never execute those specs.
export default defineConfig({
  test: {
    exclude: [
      ...configDefaults.exclude,
      "e2e/**",
      "lib/e2e-api-lifecycle.test.ts",
      "lib/e2e-python-runtime.test.ts",
      "lib/e2e-sandbox.test.ts"
    ]
  }
});
