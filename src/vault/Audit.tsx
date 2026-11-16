import { useEffect, useMemo, useState, type ReactNode } from "react";
import {
  ArrowRight,
  CalendarClock,
  CircleCheck,
  Copy,
  LoaderCircle,
  RefreshCw,
  ShieldCheck,
  ShieldExclamationPoint,
  ShieldX,
  WifiOff,
} from "lucide-react";
import { errorText } from "../api";
import {
  auditApi,
  KIND_ORDER,
  type AuditFinding,
  type AuditReport,
  type PasswordFindingKind,
} from "../lib/api-audit";
import { Button } from "../ui/Button";
import "../styles/audit.css";

/**
 * Security audit — weak, reused and breached passwords, plus expiring
 *
 * Props:
 * - `onFix(itemId, fieldId)` opens the item editor at that field with the
 *   generator ready. The parent owns navigation; this view only reports what
 *   needs attention.
 * - `onError(message)` is optional and receives user-readable failures. The
 *   view also renders inline errors, so a parent without a toast surface is
 *   still correct.
 */
export default function Audit({
  onFix,
  onError,
}: {
  onFix: (itemId: string, fieldId: string) => void;
  onError?: (message: string) => void;
}) {
  const [report, setReport] = useState<AuditReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);

  useEffect(() => {
    let live = true;
    setError(null);
    auditApi
      .report()
      .then((next) => {
        if (live) setReport(next);
      })
      .catch((reason) => {
        if (!live) return;
        const message = errorText(reason);
        setError(message);
        onError?.(message);
      });
    return () => {
      live = false;
    };
    // The offline pass runs once per mount; `onError` is a notification hook,
    // not a dependency of the read.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const groups = useMemo(() => {
    if (!report) return [];
    return KIND_ORDER.map((kind) => ({
      kind,
      findings: report.findings.filter((finding) => finding.kind === kind),
    }));
  }, [report]);

  // Expired first, then the nearest date. The core computes `daysUntil`, so
  // the renderer never re-derives a date from the local clock.
  const expiryFindings = useMemo(() => {
    if (!report) return [];
    return report.findings
      .filter(
        (finding) => finding.kind === "expired" || finding.kind === "expiring",
      )
      .sort((a, b) => (a.daysUntil ?? 0) - (b.daysUntil ?? 0));
  }, [report]);

  async function checkBreaches() {
    setChecking(true);
    setError(null);
    try {
      const next = await auditApi.checkBreaches();
      setReport(next);
    } catch (reason) {
      const message = errorText(reason);
      setError(message);
      onError?.(message);
    } finally {
      setChecking(false);
    }
  }

  function retry() {
    setReport(null);
    setError(null);
    auditApi
      .report()
      .then(setReport)
      .catch((reason) => {
        const message = errorText(reason);
        setError(message);
        onError?.(message);
      });
  }

  const findings = report?.findings ?? [];
  const hasFindings = findings.length > 0;

  return (
    <section className="panel-page" aria-label="Security audit">
      <header className="panel-head">
        <span className="eyebrow">Security · this device</span>
        <h1 className="panel-title">Security audit</h1>
        <p className="panel-sub">
          Weak, reused, and breached passwords, plus credentials that are
          expiring, tallied by the Rust core. This page never receives a
          password value — only the item, the field, and a description of what
          is wrong.
        </p>
      </header>

      <div className="panel-scroll">
        <div className="panel-column audit-column">
          {error && (
            <div className="audit-banner is-danger" role="alert">
              <ShieldX size={16} aria-hidden />
              <div className="audit-banner-copy">
                <strong>The audit could not finish</strong>
                <span>{error}</span>
              </div>
              <Button
                size="sm"
                variant="secondary"
                leading={<RefreshCw size={13} aria-hidden />}
                onClick={retry}
              >
                Try again
              </Button>
            </div>
          )}

          {!report && !error && (
            <div className="audit-loading" role="status">
              <LoaderCircle className="audit-spin" size={18} aria-hidden />
              <span>Reading the vault…</span>
            </div>
          )}

          {report && (
            <>
              <div className="audit-counters">
                <CounterCard
                  kind="weak"
                  value={report.weak}
                  label="Weak"
                  note="Checked on this device"
                  icon={<ShieldExclamationPoint size={16} aria-hidden />}
                />
                <CounterCard
                  kind="reused"
                  value={report.reused}
                  label="Reused"
                  note="Checked on this device"
                  icon={<Copy size={16} aria-hidden />}
                />
                <CounterCard
                  kind="breached"
                  value={report.breached}
                  label="Breached"
                  note={
                    report.breachChecked
                      ? "Checked against a breach range; the password never leaves the core."
                      : "Not checked against breach data yet."
                  }
                  icon={<ShieldX size={16} aria-hidden />}
                />
              </div>

              <section className="card audit-check" aria-labelledby="audit-check-title">
                <div className="audit-check-main">
                  <h2 className="card-title" id="audit-check-title">
                    <ShieldCheck size={15} aria-hidden /> Breach check is
                    k-anonymous
                  </h2>
                  <p className="audit-k-anon">
                    Weak and reuse checks never touch the network. A breach
                    check sends only the first five characters of a SHA-1 hash
                    to Have I Been Pwned; the service answers with a whole hash
                    range, and the comparison runs in the core. The password
                    itself never leaves the process.
                  </p>
                </div>
                <Button
                  variant="primary"
                  leading={
                    checking ? (
                      <LoaderCircle className="audit-spin" size={14} aria-hidden />
                    ) : (
                      <ShieldCheck size={14} aria-hidden />
                    )
                  }
                  disabled={checking}
                  onClick={() => {
                    void checkBreaches();
                  }}
                >
                  {checking ? "Checking…" : "Check breaches"}
                </Button>
              </section>

              {!report.breachChecked && (
                <div
                  className={`audit-banner ${report.breachNote ? "is-warn" : "is-info"}`}
                  role="status"
                >
                  {report.breachNote ? (
                    <WifiOff size={16} aria-hidden />
                  ) : (
                    <ShieldCheck size={16} aria-hidden />
                  )}
                  <div className="audit-banner-copy">
                    <strong>
                      {report.breachNote
                        ? "Breach data is unavailable"
                        : "Breaches not checked yet"}
                    </strong>
                    <span>
                      {report.breachNote ??
                        "Strength and reuse are already checked on this device. Run a breach check to add the online pass."}
                    </span>
                  </div>
                </div>
              )}

              <section
                className="audit-group audit-expiry"
                aria-labelledby="audit-group-expiring"
              >
                <div className="audit-group-head">
                  <CalendarClock size={14} aria-hidden />
                  <h2 className="audit-group-title" id="audit-group-expiring">
                    Expiring soon
                  </h2>
                  <span
                    className="audit-group-count"
                    aria-label={`${report?.expiring ?? 0} expiring, ${report?.expired ?? 0} expired`}
                  >
                    {report?.expired ? `${report.expired} expired · ` : ""}
                    {report?.expiring ?? 0} expiring
                  </span>
                </div>
                {expiryFindings.length === 0 ? (
                  <div className="audit-expiry-empty">
                    <CircleCheck size={15} aria-hidden />
                    <span>
                      Nothing is expiring in the next 30 days — no credential
                      date is near or past.
                    </span>
                  </div>
                ) : (
                  <ul className="audit-findings">
                    {expiryFindings.map((finding) => (
                      <ExpiryRow
                        key={`${finding.itemId}:${finding.fieldId}:${finding.kind}`}
                        finding={finding}
                        onFix={onFix}
                      />
                    ))}
                  </ul>
                )}
              </section>

              {!hasFindings ? (
                <div className="audit-empty">
                  <span className="audit-empty-glyph">
                    <CircleCheck size={22} aria-hidden />
                  </span>
                  <h2 className="audit-empty-title">Nothing to fix</h2>
                  <p className="audit-empty-copy">
                    {report.breachChecked
                      ? "No weak, reused, or breached passwords were found in the live items."
                      : "No weak or reused passwords were found in the live items."}
                  </p>
                </div>
              ) : (
                groups.map(({ kind, findings: group }) =>
                  group.length === 0 ? null : (
                    <section
                      className="audit-group"
                      key={kind}
                      aria-labelledby={`audit-group-${kind}`}
                    >
                      <div className="audit-group-head">
                        {kindIcon(kind)}
                        <h2 className="audit-group-title" id={`audit-group-${kind}`}>
                          {kindLabel(kind)}
                        </h2>
                        <span className="audit-group-count">{group.length}</span>
                      </div>
                      <ul className="audit-findings">
                        {group.map((finding) => (
                          <FindingRow
                            key={`${finding.itemId}:${finding.fieldId}:${finding.kind}`}
                            finding={finding}
                            onFix={onFix}
                          />
                        ))}
                      </ul>
                    </section>
                  ),
                )
              )}
            </>
          )}
        </div>
      </div>
    </section>
  );
}

function CounterCard({
  kind,
  value,
  label,
  note,
  icon,
}: {
  kind: PasswordFindingKind;
  value: number;
  label: string;
  note: string;
  icon: ReactNode;
}) {
  return (
    <div
      className="audit-counter"
      data-kind={kind}
      role="group"
      aria-label={`${label}: ${value}`}
    >
      <div className="audit-counter-head">
        <span className="audit-counter-icon">{icon}</span>
        <span className="audit-counter-label">{label}</span>
      </div>
      <span className="audit-counter-value">{value}</span>
      <span className="audit-counter-note">{note}</span>
    </div>
  );
}

function FindingRow({
  finding,
  onFix,
}: {
  finding: AuditFinding;
  onFix: (itemId: string, fieldId: string) => void;
}) {
  return (
    <li className="audit-finding">
      <div className="audit-finding-main">
        <span className="audit-finding-title" title={finding.title}>
          {finding.title}
        </span>
        <span className="audit-finding-meta">
          {finding.fieldLabel} · {finding.detail}
        </span>
      </div>
      <Button
        size="sm"
        variant="secondary"
        trailing={<ArrowRight size={13} aria-hidden />}
        onClick={() => onFix(finding.itemId, finding.fieldId)}
        aria-label={`Fix ${finding.title}, ${finding.fieldLabel}`}
      >
        Fix
      </Button>
    </li>
  );
}

function ExpiryRow({
  finding,
  onFix,
}: {
  finding: AuditFinding;
  onFix: (itemId: string, fieldId: string) => void;
}) {
  return (
    <li className="audit-finding" data-kind={finding.kind}>
      <div className="audit-finding-main">
        <span className="audit-finding-title" title={finding.title}>
          {finding.title}
        </span>
        <span className="audit-finding-meta">
          {finding.fieldLabel} · {expiryPhrase(finding)}
          {finding.date && (
            <>
              {" · "}
              <time dateTime={finding.date} title={finding.detail}>
                {finding.date}
              </time>
            </>
          )}
        </span>
      </div>
      <Button
        size="sm"
        variant="secondary"
        trailing={<ArrowRight size={13} aria-hidden />}
        onClick={() => onFix(finding.itemId, finding.fieldId)}
        aria-label={`Open ${finding.title}, ${finding.fieldLabel}`}
      >
        Open
      </Button>
    </li>
  );
}

/** Relative wording for an expiry finding, in whole days from today. */
function expiryPhrase(finding: AuditFinding): string {
  const days = finding.daysUntil;
  if (days == null) {
    return finding.kind === "expired" ? "expired" : "expires soon";
  }
  if (days === 0) return "expires today";
  if (days === 1) return "expires tomorrow";
  if (days === -1) return "expired yesterday";
  return days < 0 ? `expired ${-days} days ago` : `expires in ${days} days`;
}

function kindLabel(kind: PasswordFindingKind): string {
  switch (kind) {
    case "breached":
      return "Breached passwords";
    case "reused":
      return "Reused passwords";
    case "weak":
      return "Weak passwords";
  }
}

function kindIcon(kind: PasswordFindingKind): ReactNode {
  switch (kind) {
    case "breached":
      return <ShieldX size={14} aria-hidden />;
    case "reused":
      return <Copy size={14} aria-hidden />;
    case "weak":
      return <ShieldExclamationPoint size={14} aria-hidden />;
  }
}
