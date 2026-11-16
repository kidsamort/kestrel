import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { applyAccent, applyTheme, storedAccent, storedTheme } from "./lib/theme";
import "./styles/fonts.css";
import "./styles/tokens.css";
import "./styles/tints.css";
import "./styles/app.css";

// Before the first paint: theme and accent are already on <html>, so there is
// no colour or typeface flash when the window appears.
applyTheme(storedTheme());
applyAccent(storedAccent());

// The palette runs in its own webview (`index.html?window=quick`). It has its
// own entry so the full shell — and its data fetching — never mounts there.
const isQuick = new URLSearchParams(window.location.search).get("window") === "quick";
// The autofill overlay runs in its own `WS_EX_NOACTIVATE` webview
// (`index.html?window=autofill`). It gets an entry of its own so the full shell
// never mounts in a window that must stay out of the way.
const isAutofill =
  new URLSearchParams(window.location.search).get("window") === "autofill";

if (isQuick) {
  void import("./quick");
} else if (isAutofill) {
  void import("./autofill");
} else {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </React.StrictMode>,
  );
}
