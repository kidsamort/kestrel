import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { Check, CircleAlert, Info, Lock } from "lucide-react";

export type Tone = "neutral" | "success" | "danger" | "warn";

interface Notice {
  id: number;
  text: string;
  detail?: string;
  tone: Tone;
}

interface NoticeApi {
  notify: (text: string, options?: { detail?: string; tone?: Tone }) => void;
}

const NoticeContext = createContext<NoticeApi | null>(null);

const ICONS = {
  neutral: Info,
  success: Check,
  danger: CircleAlert,
  warn: Lock,
} as const;

export function NoticeProvider({ children }: { children: ReactNode }) {
  const [notices, setNotices] = useState<Notice[]>([]);
  const counter = useRef(0);

  const notify = useCallback(
    (text: string, options?: { detail?: string; tone?: Tone }) => {
      counter.current += 1;
      const id = counter.current;
      setNotices((current) => [
        ...current.slice(-2),
        { id, text, detail: options?.detail, tone: options?.tone ?? "success" },
      ]);
      window.setTimeout(() => {
        setNotices((current) => current.filter((n) => n.id !== id));
      }, 3200);
    },
    [],
  );

  const api = useMemo(() => ({ notify }), [notify]);

  return (
    <NoticeContext.Provider value={api}>
      {children}
      <div className="notices" aria-live="polite" aria-atomic="false">
        {notices.map((notice) => {
          const Icon = ICONS[notice.tone];
          return (
            <div key={notice.id} className={`notice notice-${notice.tone}`}>
              <Icon size={14} aria-hidden className="notice-icon" />
              <div className="notice-copy">
                <span className="notice-text">{notice.text}</span>
                {notice.detail ? (
                  <span className="notice-detail">{notice.detail}</span>
                ) : null}
              </div>
            </div>
          );
        })}
      </div>
    </NoticeContext.Provider>
  );
}

export function useNotify(): NoticeApi["notify"] {
  const api = useContext(NoticeContext);
  if (!api) throw new Error("useNotify must be used inside NoticeProvider");
  return api.notify;
}
