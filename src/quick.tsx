import React from "react";
import ReactDOM from "react-dom/client";
// Styles first: they must land in the document before `QuickAccess` (which
// also imports `quick.css`) is evaluated, so quick.css keeps overriding the
// shared `.palette-*` rules from app.css.
import "./styles/fonts.css";
import "./styles/tokens.css";
import "./styles/tints.css";
import "./styles/app.css";
import "./styles/quick.css";
import QuickAccess from "./QuickAccess";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { applyAccent, applyTheme, storedAccent, storedTheme } from "./lib/theme";

/**
 * Entry for the palette webview (`index.html?window=quick`). The shell builds
 * this window lazily; `index.html` / `main.tsx` must route that query here
 * instead of mounting the full app.
 *
 * Theme and accent are applied before the first paint, so the palette opens in
 * the same graphite/accent pair as the main window.
 */
applyTheme(storedTheme());
applyAccent(storedAccent());

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <QuickAccess />
    </ErrorBoundary>
  </React.StrictMode>,
);
