import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

// Next 16.2.11 remains the stable framework pin. Its dependency range permits
// vulnerable PostCSS releases, so package.json applies one scoped correction:
// next -> postcss@8.5.12, the first version patched for CVE-2026-45623.
export default defineConfig([
  ...nextVitals,
  ...nextTypescript,
  {
    settings: {
      next: {
        rootDir: "apps/console/",
      },
    },
    rules: {
      "@next/next/no-html-link-for-pages": "off",
    },
  },
  {
    files: ["**/*.{js,jsx,ts,tsx}"],
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],
    },
  },
  globalIgnores([
    ".claude/**",
    ".codex-leader-worktrees/**",
    "**/.next/**",
    "**/out/**",
    "**/build/**",
    "**/dist/**",
    "**/coverage/**",
    "**/playwright-report/**",
    "**/test-results/**",
    "**/next-env.d.ts",
  ]),
]);
