import type { RefObject } from "react";
import { CircleAlert, Lock, ScanFace } from "lucide-react";
import type { HelloStatus, VaultState } from "../types";
import { BrandMark } from "../ui/BrandMark";
import { Button } from "../ui/Button";
import { TextField } from "../ui/Input";

/**
 * The three non-search surfaces of the palette: a core that cannot be reached,
 * the boot skeleton, and the locked door (initialised or not).
 */
export function QuickLocked({
  bootError,
  vault,
  password,
  unlocking,
  unlockError,
  passwordRef,
  onPasswordChange,
  onSubmit,
  onOpenMain,
  hello,
  helloBusy,
  onHelloUnlock,
}: {
  bootError: string | null;
  vault: VaultState | null;
  password: string;
  unlocking: boolean;
  unlockError: string | null;
  passwordRef: RefObject<HTMLInputElement | null>;
  onPasswordChange: (value: string) => void;
  onSubmit: (event: React.FormEvent) => void;
  onOpenMain: () => void;
  hello: HelloStatus | null;
  helloBusy: boolean;
  onHelloUnlock: () => void;
}) {
  if (bootError) {
    return (
      <div className="qa-locked">
        <span className="qa-seal" aria-hidden="true">
          <CircleAlert size={18} strokeWidth={1.4} />
        </span>
        <h1 className="empty-title">Quick access is unavailable.</h1>
        <p className="empty-copy">{bootError}</p>
      </div>
    );
  }

  if (vault === null) {
    return (
      <div className="qa-results qa-results-bare" aria-busy="true">
        {[0, 1, 2, 3].map((n) => (
          <div
            className="row-skeleton"
            key={n}
            style={{ opacity: 1 - n * 0.18 }}
          />
        ))}
      </div>
    );
  }

  return (
    <form className="qa-locked" onSubmit={onSubmit}>
      <span className="qa-seal" aria-hidden="true">
        <Lock size={18} strokeWidth={1.4} />
      </span>
      {vault.initialized ? (
        <>
          <h1 className="empty-title">The vault is locked.</h1>
          <p className="empty-copy">
            Unlock here or in the main window — the palette shares one session,
            so either door opens both.
          </p>
          <TextField
            ref={passwordRef}
            label="Master password"
            type="password"
            autoComplete="current-password"
            value={password}
            error={unlockError}
            onChange={(event) => onPasswordChange(event.target.value)}
          />
          <Button
            type="submit"
            variant="primary"
            size="sm"
            block
            disabled={!password || unlocking || helloBusy}
            trailing={<Lock size={13} aria-hidden />}
          >
            {unlocking ? "Unlocking…" : "Unlock"}
          </Button>
          {hello?.enrolled && hello.available ? (
            <Button
              type="button"
              variant="secondary"
              size="sm"
              block
              disabled={unlocking || helloBusy}
              leading={<ScanFace size={13} aria-hidden />}
              onClick={onHelloUnlock}
            >
              {helloBusy ? "Waiting for Windows Hello…" : "Unlock with Hello"}
            </Button>
          ) : null}
        </>
      ) : (
        <>
          <h1 className="empty-title">No vault on this device yet.</h1>
          <p className="empty-copy">
            A master password is created once, in the main window. The palette
            reads the same sealed store.
          </p>
          <Button variant="primary" size="sm" block onClick={onOpenMain}>
            Open the main window
          </Button>
        </>
      )}
      <span className="qa-locked-foot">
        <BrandMark size={13} />
        Keys stay in the core; this window only draws rows.
      </span>
    </form>
  );
}
