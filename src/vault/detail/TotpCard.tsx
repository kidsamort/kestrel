import { useCallback, useEffect, useRef, useState } from "react";
import { Check, CircleAlert, Copy } from "lucide-react";
import { api, errorText } from "../../api";
import type { CopyApi } from "../../lib/copy";
import { Tip } from "../../ui/Tooltip";

/**
 * The core computes the code and reports the window it belongs to; this
 * component only counts down that window and asks for the next code when it
 * rolls over.
 */
/** Fallback only while the first response is in flight. */
const TOTP_PERIOD = 30;

export default function TotpCard({
  itemId,
  copiedKey,
  onCopy,
}: {
  itemId: string;
  copiedKey: string | null;
  onCopy: CopyApi["copyText"];
}) {
  const [code, setCode] = useState<string | null>(null);
  const [remaining, setRemaining] = useState(0);
  const [period, setPeriod] = useState(TOTP_PERIOD);
  const [failed, setFailed] = useState<string | null>(null);
  const mounted = useRef(true);

  const load = useCallback(() => {
    api
      .totp(itemId)
      .then((totp) => {
        if (!mounted.current) return;
        setCode(totp.code);
        setRemaining(totp.secondsRemaining);
        setPeriod(totp.period > 0 ? totp.period : TOTP_PERIOD);
        setFailed(null);
      })
      .catch((error) => {
        if (!mounted.current) return;
        setFailed(errorText(error));
        // A transient core failure must not leave the card dead: park the
        // countdown a few seconds so the rollover effect tries again instead
        // of hammering the core once per second.
        setRemaining(3);
      });
  }, [itemId]);

  useEffect(() => {
    mounted.current = true;
    load();
    return () => {
      mounted.current = false;
    };
  }, [load]);

  useEffect(() => {
    // The updater only counts down: a side effect inside it would run twice
    // under StrictMode and fire two `api.totp` requests for one rollover.
    const tick = window.setInterval(() => {
      setRemaining((current) => (code === null ? current : Math.max(0, current - 1)));
    }, 1000);
    return () => window.clearInterval(tick);
  }, [code]);

  // Rollover is observed rather than triggered: when the countdown reaches
  // zero the code is fetched once for the new window.
  useEffect(() => {
    if (code === null || remaining > 0) return;
    load();
  }, [code, remaining, load]);

  const grouped = code
    ? code.length > 6
      ? `${code.slice(0, code.length - 3)} ${code.slice(-3)}`
      : `${code.slice(0, 3)} ${code.slice(3)}`
    : "——— ———";
  // Urgency is carried by colour only after it is real: calm while there is
  // time to type the code, amber while it is tight, red in the last seconds.
  const phase = remaining > 10 ? "calm" : remaining > 5 ? "warn" : "urgent";
  const fraction = Math.max(0, Math.min(100, (remaining / period) * 100));

  return (
    <section className={`block totp totp--${phase}`} aria-label="Authenticator code">
      <h2 className="block-title">Authenticator</h2>
      {failed ? (
        <span className="totp-failed">
          <CircleAlert size={13} aria-hidden /> {failed}
        </span>
      ) : (
        <div className="totp-line">
          <span
            className="totp-state"
            style={{ ["--p" as string]: fraction }}
            aria-hidden
          />
          <span className="totp-code">{grouped}</span>
          {code ? (
            <Tip label="Copy code">
              <button
                type="button"
                className="icon-btn totp-copy"
                aria-label="Copy one-time code"
                onClick={() => onCopy(code, "one-time code")}
              >
                {copiedKey === "text:one-time code" ? (
                  <Check size={15} className="copy-done" aria-hidden />
                ) : (
                  <Copy size={15} strokeWidth={1.6} aria-hidden />
                )}
              </button>
            </Tip>
          ) : null}
        </div>
      )}
    </section>
  );
}
