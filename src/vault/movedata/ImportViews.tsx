/**
 * Presentational halves of the import flow: the row preview and the report
 * card. Both are pure views — the flow owns the state and the core calls.
 */
import { Check, CircleAlert, Upload } from "lucide-react";
import type { ImportPreview, ImportReport } from "../../lib/api-portability";
import { CATEGORIES } from "../../types";
import { Button } from "../../ui/Button";

const CATEGORY_LABELS = new Map<string, string>(
  CATEGORIES.map((entry): [string, string] => [entry.id, entry.label]),
);

const STEPS = ["Choose file", "Preview", "Report"];

export function ImportSteps({ step }: { step: number }) {
  return (
    <ol className="mv-steps" aria-label="Import steps">
      {STEPS.map((label, index) => {
        const number = index + 1;
        return (
          <li
            key={label}
            className={
              number === step ? "is-active" : number < step ? "is-done" : ""
            }
            aria-current={number === step ? "step" : undefined}
          >
            <span className="mv-step-num" aria-hidden>
              {number < step ? <Check size={9} aria-hidden /> : number}
            </span>
            {label}
          </li>
        );
      })}
    </ol>
  );
}

export function ImportPreviewView({
  preview,
  importing,
  disabled,
  onImport,
}: {
  preview: ImportPreview;
  importing: boolean;
  disabled: boolean;
  onImport: () => void;
}) {
  return (
    <div className="mv-preview">
      <p className="mv-preview-total">
        {preview.total === 1 ? "1 item ready" : `${preview.total} items ready`}
        {preview.total > preview.sample.length
          ? ` · previewing the first ${preview.sample.length}`
          : ""}
      </p>
      {preview.sample.length > 0 ? (
        <table className="mv-table">
          <thead>
            <tr>
              <th scope="col">Title</th>
              <th scope="col">Category</th>
              <th scope="col" className="mv-num">
                Fields
              </th>
            </tr>
          </thead>
          <tbody>
            {preview.sample.map((row, index) => (
              <tr key={`${index}-${row.title}`}>
                <td title={row.title}>{row.title}</td>
                <td>{CATEGORY_LABELS.get(row.category) ?? row.category}</td>
                <td className="mv-num">{row.fieldCount}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p className="mv-empty">No importable rows were found in this file.</p>
      )}
      <div className="mv-actions">
        <Button
          variant="primary"
          size="sm"
          leading={<Upload size={13} aria-hidden />}
          disabled={disabled}
          onClick={onImport}
        >
          {importing
            ? "Importing…"
            : preview.total === 1
              ? "Import 1 item"
              : `Import ${preview.total} items`}
        </Button>
      </div>
    </div>
  );
}

export function ImportReportView({
  report,
  onReset,
}: {
  report: ImportReport;
  onReset: () => void;
}) {
  return (
    <div
      className={`mv-report ${report.failed.length > 0 ? "is-partial" : ""}`}
      role="status"
      aria-live="polite"
    >
      <p className="mv-report-head">
        {report.failed.length > 0 ? (
          <CircleAlert size={14} aria-hidden />
        ) : (
          <Check size={14} aria-hidden />
        )}
        <strong>Import report</strong>
      </p>
      <dl className="mv-report-counts">
        <div>
          <dt>Imported</dt>
          <dd className="mono">{report.imported}</dd>
        </div>
        <div>
          <dt>Skipped</dt>
          <dd className="mono">{report.skipped}</dd>
        </div>
        <div className={report.failed.length > 0 ? "is-bad" : ""}>
          <dt>Failed</dt>
          <dd className="mono">{report.failed.length}</dd>
        </div>
      </dl>
      {report.failed.length > 0 ? (
        <ul className="mv-failures">
          {report.failed.map((failure) => (
            <li key={`${failure.row}-${failure.reason}`}>
              <span className="mono">Row {failure.row}</span>
              {failure.reason}
            </li>
          ))}
        </ul>
      ) : null}
      <div className="mv-actions">
        <Button variant="secondary" size="sm" onClick={onReset}>
          Import another file
        </Button>
      </div>
    </div>
  );
}
