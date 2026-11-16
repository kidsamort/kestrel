import { useRef } from "react";
import {
  Lock,
  Settings2,
  ShieldAlert,
  Star,
  Trash2,
  Vault,
  Wand2,
  type LucideIcon,
} from "lucide-react";
import { CATEGORY_META } from "../lib/catalog";
import type { Filter, Panel } from "../lib/navigation";
import { filterKey } from "../lib/navigation";
import type { Counts } from "../types";
import { CategoryGlyph } from "../ui/CategoryGlyph";
import { Tip } from "../ui/Tooltip";

interface Props {
  filter: Filter;
  panel: Panel;
  /** Core counters; null until the first response lands. */
  counts: Counts | null;
  compact: boolean;
  onFilter: (filter: Filter) => void;
  onPanel: (panel: Panel) => void;
  onLock: () => void;
}

export default function Sidebar({
  filter,
  panel,
  counts: coreCounts,
  compact,
  onFilter,
  onPanel,
  onLock,
}: Props) {
  const navRef = useRef<HTMLElement>(null);
  const favorites = coreCounts?.favorites ?? 0;
  const trashCount = coreCounts?.trash ?? 0;

  // Arrow keys walk the filter column like a menu, without stealing Tab.
  function onKeyDown(event: React.KeyboardEvent<HTMLElement>) {
    if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
    const buttons = Array.from(
      navRef.current?.querySelectorAll<HTMLButtonElement>(
        ".side-item:not([disabled])",
      ) ?? [],
    );
    const index = buttons.indexOf(document.activeElement as HTMLButtonElement);
    if (index === -1) return;
    event.preventDefault();
    const next = event.key === "ArrowDown" ? index + 1 : index - 1;
    const target = buttons[(next + buttons.length) % buttons.length];
    target?.focus();
  }

  const activeKey = panel === "vault" ? filterKey(filter) : panel;

  return (
    <nav
      className={`sidebar ${compact ? "sidebar-compact" : ""}`}
      aria-label="Vault"
      ref={navRef}
      onKeyDown={onKeyDown}
    >
      <div className="side-scroll">
        <div className="side-group">
          <SideItem
            compact={compact}
            label="All items"
            icon={Vault}
            count={coreCounts?.total ?? 0}
            active={activeKey === "all"}
            onClick={() => onFilter({ mode: "all" })}
            hotkey="Ctrl 1"
          />
          <SideItem
            compact={compact}
            label="Favorites"
            icon={Star}
            count={favorites}
            active={activeKey === "favorites"}
            onClick={() => onFilter({ mode: "favorites" })}
            hotkey="Ctrl 2"
          />
          <SideItem
            compact={compact}
            label="Trash"
            icon={Trash2}
            count={trashCount}
            active={activeKey === "trash"}
            onClick={() => onPanel("trash")}
          />
        </div>

        <div className="side-group">
          {!compact ? (
            <h2 className="side-heading">Categories</h2>
          ) : (
            <div className="side-rule" aria-hidden="true" />
          )}
          {CATEGORY_META.map((meta) => {
            const count = coreCounts?.categories[meta.id] ?? 0;
            const active = activeKey === `category:${meta.id}`;
            const button = (
              <button
                key={meta.id}
                type="button"
                className={`side-item ${active ? "is-active" : ""} ${
                  count === 0 ? "is-empty" : ""
                }`}
                aria-current={active ? "true" : undefined}
                aria-label={compact ? `${meta.label}, ${count} items` : undefined}
                onClick={() =>
                  onFilter({ mode: "category", category: meta.id })
                }
              >
                <span className="side-icon">
                  <CategoryGlyph category={meta.id} size={15} />
                </span>
                {!compact ? (
                  <span className="side-label">{meta.label}</span>
                ) : null}
                {!compact ? (
                  <span className="side-count" aria-hidden="true">
                    {count}
                  </span>
                ) : null}
              </button>
            );
            return compact ? (
              <Tip key={meta.id} label={meta.label} side="right">
                {button}
              </Tip>
            ) : (
              button
            );
          })}
        </div>
      </div>

      <div className="side-foot">
        <SideItem
          compact={compact}
          label="Security audit"
          icon={ShieldAlert}
          active={activeKey === "audit"}
          onClick={() => onPanel("audit")}
        />
        <SideItem
          compact={compact}
          label="Generator"
          icon={Wand2}
          active={activeKey === "generator"}
          onClick={() => onPanel("generator")}
          hotkey="Ctrl G"
        />
        <SideItem
          compact={compact}
          label="Settings"
          icon={Settings2}
          active={activeKey === "settings"}
          onClick={() => onPanel("settings")}
          hotkey="Ctrl ,"
        />
        <SideItem
          compact={compact}
          label="Lock vault"
          icon={Lock}
          onClick={onLock}
          hotkey="Ctrl L"
        />
      </div>
    </nav>
  );
}

function SideItem({
  label,
  icon: Icon,
  count,
  active,
  onClick,
  compact,
  hotkey,
}: {
  label: string;
  icon: LucideIcon;
  count?: number;
  active?: boolean;
  onClick: () => void;
  compact: boolean;
  hotkey?: string;
}) {
  const button = (
    <button
      type="button"
      className={`side-item ${active ? "is-active" : ""}`}
      aria-current={active ? "true" : undefined}
      aria-label={compact ? label : undefined}
      onClick={onClick}
    >
      <span className="side-icon">
        <Icon size={15} strokeWidth={1.5} aria-hidden />
      </span>
      {!compact ? <span className="side-label">{label}</span> : null}
      {!compact && typeof count === "number" ? (
        <span className="side-count" aria-hidden="true">
          {count}
        </span>
      ) : null}
    </button>
  );
  return compact ? (
    <Tip label={label} side="right" keys={hotkey}>
      {button}
    </Tip>
  ) : (
    button
  );
}
