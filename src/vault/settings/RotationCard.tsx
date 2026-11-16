/**
 * Settings → Master password rotation. Validation stays local so a typo never
 * reaches the core; the core still re-checks the current password.
 */
import { useState, type FormEvent } from "react";
import { Check, KeyRound } from "lucide-react";
import { api, errorText } from "../../api";
import type { VaultState } from "../../types";
import { Button } from "../../ui/Button";
import { TextField } from "../../ui/Input";
import { useNotify } from "../../ui/Toast";

export default function RotationCard({
  onState,
}: {
  onState: (state: VaultState) => void;
}) {
  const notify = useNotify();
  const [oldPassword, setOldPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [rotating, setRotating] = useState(false);
  const [rotateError, setRotateError] = useState<string | null>(null);
  const [rotated, setRotated] = useState(false);

  async function rotate(event: FormEvent) {
    event.preventDefault();
    setRotateError(null);
    setRotated(false);
    if (newPassword.length < 10) {
      setRotateError("A master password needs at least 10 characters.");
      return;
    }
    if (newPassword !== confirm) {
      setRotateError("The new passwords do not match.");
      return;
    }
    if (newPassword === oldPassword) {
      setRotateError("The new password is the same as the current one.");
      return;
    }
    setRotating(true);
    try {
      const next = await api.changePassword(oldPassword, newPassword);
      onState(next);
      setOldPassword("");
      setNewPassword("");
      setConfirm("");
      setRotated(true);
      notify("Master password changed", {
        detail: "Every item was re-encrypted under a new salt.",
        tone: "success",
      });
    } catch (error) {
      setRotateError(errorText(error));
    } finally {
      setRotating(false);
    }
  }

  return (
    <section className="card" aria-labelledby="rotate-title">
      <div className="card-head">
        <h2 className="card-title" id="rotate-title">
          <KeyRound size={15} aria-hidden /> Master password
        </h2>
      </div>
      <p className="card-copy">
        Rotating derives a new master key and re-encrypts every item under a
        fresh salt. It cannot be undone, and there is no recovery key.
      </p>
      <form className="card-form" onSubmit={rotate}>
        <TextField
          label="Current master password"
          type="password"
          value={oldPassword}
          autoComplete="current-password"
          onChange={(event) => {
            setOldPassword(event.target.value);
            setRotated(false);
          }}
        />
        <div className="form-grid">
          <TextField
            label="New master password"
            type="password"
            value={newPassword}
            autoComplete="new-password"
            onChange={(event) => {
              setNewPassword(event.target.value);
              setRotated(false);
            }}
          />
          <TextField
            label="Confirm new password"
            type="password"
            value={confirm}
            autoComplete="new-password"
            onChange={(event) => {
              setConfirm(event.target.value);
              setRotated(false);
            }}
          />
        </div>
        {rotateError ? (
          <p className="form-error" role="alert">
            {rotateError}
          </p>
        ) : null}
        {rotated ? (
          <p className="form-ok" role="status">
            <Check size={13} aria-hidden /> Re-encrypted under the new key.
          </p>
        ) : null}
        <div className="form-actions">
          <Button
            type="submit"
            variant="primary"
            size="sm"
            disabled={rotating || !oldPassword || !newPassword || !confirm}
          >
            {rotating ? "Re-encrypting every item…" : "Change master password"}
          </Button>
        </div>
      </form>
    </section>
  );
}
