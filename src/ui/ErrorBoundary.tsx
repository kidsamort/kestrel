import { Component, type ErrorInfo, type ReactNode } from "react";
import { CircleAlert } from "lucide-react";
import { Button } from "./Button";

interface Props {
  children: ReactNode;
}

interface State {
  failed: boolean;
}

/**
 * Last-resort guard for the renderer. A render error in any screen must not
 * leave the window blank: the user gets a reload affordance and the stack goes
 * to the console only, never into the DOM.
 *
 * Class component because error boundaries have no hook equivalent.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { failed: false };

  static getDerivedStateFromError(): State {
    return { failed: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("Unhandled interface error:", error, info.componentStack);
  }

  render(): ReactNode {
    if (!this.state.failed) return this.props.children;

    return (
      <div className="fatal">
        <div className="fatal-card" role="alert">
          <span className="fatal-icon" aria-hidden>
            <CircleAlert size={20} strokeWidth={1.5} />
          </span>
          <h1 className="display-sm">Something went wrong</h1>
          <p className="fatal-copy">
            The interface hit an unexpected error. Your vault is unaffected;
            reload to continue.
          </p>
          <Button
            variant="primary"
            size="sm"
            onClick={() => window.location.reload()}
          >
            Reload
          </Button>
        </div>
      </div>
    );
  }
}
