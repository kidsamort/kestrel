import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// Tests run against the same React plugin the app is built with, so JSX
// transforms behave identically. No aliases: every module is imported by its
// real relative path, which keeps the tests honest about the code under test.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
  },
});
