/**
 * Move data → import: file → preview → report, one step at a time.
 *
 * The flow owns its file input and request ticket: a slow preview from a
 * previous file must never overwrite the newer one, so every load carries a
 * sequence number and only the latest may touch state.
 */
import { useRef, useState, type ChangeEvent } from "react";
import { FileUp } from "lucide-react";
import { errorText } from "../../api";
import {
  formatFromFileName,
  portability,
  type ImportFormat,
  type ImportPreview,
  type ImportReport,
} from "../../lib/api-portability";
import { Button } from "../../ui/Button";
import Select from "../../ui/Select";
import { useNotify } from "../../ui/Toast";
import { FORMATS } from "./formats";
import { ImportPreviewView, ImportReportView, ImportSteps } from "./ImportViews";

export default function ImportFlow({
  onError,
  onChanged,
}: {
  onError?: (message: string) => void;
  /** Called once an import wrote rows, so the shell refreshes its lists. */
  onChanged?: () => void;
}) {
  const notify = useNotify();
  const inputRef = useRef<HTMLInputElement>(null);
  const request = useRef(0);

  const [file, setFile] = useState<{ name: string; bytes: Uint8Array } | null>(null);
  const [format, setFormat] = useState<ImportFormat>("json");
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [report, setReport] = useState<ImportReport | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [busy, setBusy] = useState<"preview" | "import" | null>(null);

  const step = report ? 3 : file ? 2 : 1;

  function fail(error: unknown): string {
    const message = errorText(error);
    onError?.(message);
    return message;
  }

  async function loadPreview(nextFormat: ImportFormat, bytes: Uint8Array) {
    const ticket = ++request.current;
    setBusy("preview");
    setPreview(null);
    setImportError(null);
    try {
      const result = await portability.preview(nextFormat, bytes);
      if (ticket === request.current) setPreview(result);
    } catch (error) {
      if (ticket === request.current) setImportError(fail(error));
    } finally {
      if (ticket === request.current) setBusy(null);
    }
  }

  async function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const chosen = event.target.files?.[0];
    // Let the same file be chosen again after a report.
    event.target.value = "";
    if (!chosen) return;
    const detected = formatFromFileName(chosen.name) ?? "json";
    setFormat(detected);
    setReport(null);
    setPreview(null);
    setImportError(null);
    try {
      const bytes = new Uint8Array(await chosen.arrayBuffer());
      setFile({ name: chosen.name, bytes });
      await loadPreview(detected, bytes);
    } catch (error) {
      setFile(null);
      setImportError(fail(error));
    }
  }

  function changeFormat(next: ImportFormat) {
    setFormat(next);
    setReport(null);
    setImportError(null);
    if (file) void loadPreview(next, file.bytes);
  }

  async function runImport() {
    if (!file) return;
    setBusy("import");
    setImportError(null);
    try {
      const result = await portability.importItems(format, file.bytes);
      setReport(result);
      setPreview(null);
      if (result.imported > 0) onChanged?.();
      notify(
        result.imported === 1 ? "Imported 1 item" : `Imported ${result.imported} items`,
        {
          detail:
            result.failed.length > 0
              ? `${result.failed.length} row(s) could not be read.`
              : "Every row became a new item.",
          tone: result.failed.length > 0 ? "warn" : "success",
        },
      );
    } catch (error) {
      setImportError(fail(error));
    } finally {
      setBusy(null);
    }
  }

  function resetImport() {
    setFile(null);
    setPreview(null);
    setReport(null);
    setImportError(null);
  }

  return (
    <div className="mv-block">
      <div className="mv-block-head">
        <h3 className="mv-block-title">Import</h3>
        <ImportSteps step={step} />
      </div>

      <div className="mv-row">
        <Button
          variant="secondary"
          size="md"
          leading={<FileUp size={13} aria-hidden />}
          disabled={busy !== null}
          onClick={() => inputRef.current?.click()}
        >
          Choose file…
        </Button>
        <span className="mv-file" title={file?.name}>
          {file ? file.name : "JSON, CSV or a .1pux archive"}
        </span>
        <div className="select-shell mv-format">
          <span className="mv-format-label">Format</span>
          <Select
            label="Import format"
            value={format}
            disabled={busy !== null}
            options={FORMATS.map((entry) => ({
              value: entry.id,
              label: entry.importLabel,
            }))}
            onChange={(value) => changeFormat(value as ImportFormat)}
          />
        </div>
        <input
          ref={inputRef}
          className="mv-file-input"
          type="file"
          accept=".json,.csv,.1pux,application/json,text/csv,application/zip"
          onChange={(event) => void chooseFile(event)}
          tabIndex={-1}
        />
      </div>

      {busy === "preview" ? (
        <p className="mv-empty" role="status">
          Reading the file…
        </p>
      ) : null}

      {importError ? (
        <p className="form-error" role="alert">
          {importError}
        </p>
      ) : null}

      {preview && !report ? (
        <ImportPreviewView
          preview={preview}
          importing={busy === "import"}
          disabled={busy !== null || preview.total === 0}
          onImport={() => void runImport()}
        />
      ) : null}

      {report ? <ImportReportView report={report} onReset={resetImport} /> : null}
    </div>
  );
}
