/**
 * Move data → export: pick a format, prove the master password, download a
 * plaintext copy. The core verifies the password before anything is produced.
 */
import { useState, type FormEvent } from "react";
import { Download, TriangleAlert } from "lucide-react";
import { errorText } from "../../api";
import {
  downloadBlob,
  portability,
  type ExportFormat,
} from "../../lib/api-portability";
import { Button } from "../../ui/Button";
import { TextField } from "../../ui/Input";
import Select from "../../ui/Select";
import { useNotify } from "../../ui/Toast";
import { FORMATS } from "./formats";

export default function ExportFlow({
  onError,
}: {
  onError?: (message: string) => void;
}) {
  const notify = useNotify();
  const [format, setFormat] = useState<ExportFormat>("json");
  const [password, setPassword] = useState("");
  const [exportError, setExportError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function fail(error: unknown): string {
    const message = errorText(error);
    onError?.(message);
    return message;
  }

  async function runExport(event: FormEvent) {
    event.preventDefault();
    if (!password) return;
    setBusy(true);
    setExportError(null);
    const stamp = new Date().toISOString().slice(0, 10);
    try {
      if (format === "1pux") {
        const bytes = await portability.export1pux(password);
        downloadBlob(`kestrel-${stamp}.1pux`, bytes, "application/zip");
      } else {
        const text = await portability.exportItems(format, password);
        downloadBlob(
          `kestrel-${stamp}.${format}`,
          text,
          format === "json" ? "application/json" : "text/csv",
        );
      }
      setPassword("");
      notify("Export downloaded", {
        detail: "The file is plaintext — delete it once the move is done.",
        tone: "warn",
      });
    } catch (error) {
      setExportError(fail(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="mv-block" onSubmit={(event) => void runExport(event)}>
      <div className="mv-block-head">
        <h3 className="mv-block-title">Export</h3>
      </div>

      <p className="mv-warning">
        <TriangleAlert size={14} aria-hidden />
        <span>
          <strong>Plaintext export.</strong> The downloaded file contains every
          password in the clear. Keep it only for the move and delete it
          afterwards.
        </span>
      </p>

      <div className="mv-export-grid">
        <div className="mv-export-format">
          <label className="field-label" htmlFor="export-format">
            Format
          </label>
          <Select
            label="Export format"
            value={format}
            disabled={busy}
            options={FORMATS.map((entry) => ({
              value: entry.id,
              label: entry.exportLabel,
            }))}
            onChange={(value) => {
              setFormat(value as ExportFormat);
              setExportError(null);
            }}
          />
        </div>
        <TextField
          label="Master password"
          type="password"
          autoComplete="current-password"
          value={password}
          disabled={busy}
          onChange={(event) => {
            setPassword(event.target.value);
            setExportError(null);
          }}
          hint="Verified by the core before anything is exported."
        />
      </div>

      {format === "1pux" ? (
        <p className="mv-hint">
          1PUX carries item data only — attachment payloads are not included.
        </p>
      ) : null}

      {exportError ? (
        <p className="form-error" role="alert">
          {exportError}
        </p>
      ) : null}

      <div className="mv-actions">
        <Button
          type="submit"
          variant="primary"
          size="md"
          leading={<Download size={13} aria-hidden />}
          disabled={busy || !password}
        >
          {busy ? "Preparing…" : "Download export"}
        </Button>
      </div>
    </form>
  );
}
