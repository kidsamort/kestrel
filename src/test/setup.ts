import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// jsdom keeps rendered containers between tests; unmounting here guarantees
// each test starts from an empty document.
afterEach(() => {
  cleanup();
});
