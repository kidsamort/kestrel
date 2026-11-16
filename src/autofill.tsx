import React from "react";
import ReactDOM from "react-dom/client";
// Styles first, so the overlay's `.af-*` rules can build on the palette
// primitives in app.css without fighting their order.
import "./styles/fonts.css";
import "./styles/tokens.css";
import "./styles/tints.css";
import "./styles/app.css";
import "./styles/autofill.css";
import Overlay from "./autofill/Overlay";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { applyAccent, applyTheme, storedAccent, storedTheme } from "./lib/theme";

/**
 * Entry for the autofill overlay (`index.html?window=autofill`).
 *
 * The window is created lazily by `src-tauri/src/autofill` and never focuses
 * itself; this surface only renders what the shell inspected and asks for an
 * explicit fill. Theme and accent are applied before the first paint so the
 * card matches the main window.
 */
applyTheme(storedTheme());
applyAccent(storedAccent());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <Overlay />
    </ErrorBoundary>
  </React.StrictMode>,
);
