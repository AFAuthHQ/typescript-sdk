import { defineConfig } from "vitest/config";

// Coverage thresholds are set at the current floor (rounded down to
// leave room for short-term noise from refactors) so the gate prevents
// regressions while still being green today. Raise these as the
// package's coverage improves; do NOT lower without discussion.
export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/__tests__/**", "src/**/*.test.ts"],
      thresholds: {
        statements: 60,
        branches: 85,
        functions: 40,
        lines: 60,
      },
    },
  },
});
