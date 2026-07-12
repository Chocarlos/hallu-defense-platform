import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "lib/e2e-api-lifecycle.test.ts",
      "lib/e2e-python-runtime.test.ts",
      "lib/e2e-sandbox.test.ts"
    ]
  }
});
