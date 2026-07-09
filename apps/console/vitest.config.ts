import { configDefaults, defineConfig } from "vitest/config";

// Playwright owns apps/console/e2e; Vitest must never execute those specs.
export default defineConfig({
  test: {
    exclude: [...configDefaults.exclude, "e2e/**"]
  }
});
