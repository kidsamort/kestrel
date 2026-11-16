import { requestSettingsSection, type SettingsSection } from "../lib/settings-jump";
import { useEffect, useMemo, useRef, useState } from "react";
import * as DialogPrimitive from "@radix-ui/react-dialog";
import {
  CornerDownLeft,
  Lock,
  Search,
  Settings2,
  Star,
  Vault,
  Wand2,
} from "lucide-react";
import { secondaryText } from "../lib/catalog";
import type { Filter, Panel } from "../lib/navigation";
import type { Category, ItemSummary } from "../types";
import { CATEGORY_META } from "../lib/catalog";
import { CategoryGlyph } from "../ui/CategoryGlyph";
import { Kbd } from "../ui/Kbd";
import { PaletteRow } from "../ui/PaletteRow";

interface Action {
  id: string;
  label: string;
  hint: string;
  glyph: React.ReactNode;
  run: () => void;
}

/** Mirrors the rail in `Settings.tsx`; a section without an entry there has no anchor. */
const SETTINGS_SECTIONS: { id: SettingsSection; label: string }[] = [
  { id: "security", label: "Security" },
  { id: "rotation", label: "Change password" },
  { id: "recovery", label: "Recovery code" },
  { id: "agent", label: "SSH agent" },
  { id: "sdk", label: "SDK" },
  { id: "mcp", label: "MCP server" },
  { id: "passkeys", label: "Passkeys" },
  { id: "account", label: "Account" },
  { id: "sync", label: "Sync" },
  { id: "quick-access", label: "Quick access" },
  { id: "autofill", label: "Autofill" },
  { id: "browser", label: "Browser" },
  { id: "data", label: "Move data" },
  { id: "appearance", label: "Appearance" },
  { id: "about", label: "About" },
];

export default function CommandPalette({
  open,
  onOpenChange,
  items,
  onSelectItem,
  onFilter,
  onPanel,
  onNew,
  onLock,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  items: ItemSummary[];
  onSelectItem: (id: string) => void;
  onFilter: (filter: Filter) => void;
  onPanel: (panel: Panel) => void;
  onNew: (category: Category) => void;
  onLock: () => void;
}) {
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setActive(0);
    }
  }, [open]);

  const actions = useMemo<Action[]>(() => {
    const all: Action[] = [
      {
        id: "go-all",
        label: "Go to all items",
        hint: "Navigate",
        glyph: <Vault size={14} aria-hidden />,
        run: () => onFilter({ mode: "all" }),
      },
      {
        id: "go-favorites",
        label: "Go to favorites",
        hint: "Navigate",
        glyph: <Star size={14} aria-hidden />,
        run: () => onFilter({ mode: "favorites" }),
      },
      {
        id: "go-generator",
        label: "Open generator",
        hint: "Navigate",
        glyph: <Wand2 size={14} aria-hidden />,
        run: () => onPanel("generator"),
      },
      {
        id: "go-settings",
        label: "Open settings",
        hint: "Navigate",
        glyph: <Settings2 size={14} aria-hidden />,
        run: () => onPanel("settings"),
      },
      // Every settings section is a command, so "mcp" finds the MCP card and
      // "ssh" finds the agent rather than only the "new ssh key" action. The
      // label carries the word "settings" so a person can narrow to them.
      ...SETTINGS_SECTIONS.map((section) => ({
        id: `settings-${section.id}`,
        label: `Settings: ${section.label}`,
        hint: "Settings",
        glyph: <Settings2 size={14} aria-hidden />,
        run: () => {
          requestSettingsSection(section.id);
          onPanel("settings");
        },
      })),
      {
        id: "lock",
        label: "Lock vault",
        hint: "Security",
        glyph: <Lock size={14} aria-hidden />,
        run: onLock,
      },
    ];
    for (const meta of CATEGORY_META) {
      all.push({
        id: `new-${meta.id}`,
        label: `New ${meta.noun.toLowerCase()}`,
        hint: "Create",
        glyph: <CategoryGlyph category={meta.id} size={14} />,
        run: () => onNew(meta.id),
      });
    }
    return all;
  }, [onFilter, onLock, onNew, onPanel]);

  const needle = query.trim().toLowerCase();
  const matchingItems = useMemo(
    () =>
      items
        .filter((item) => {
          if (!needle) return true;
          return (
            item.title.toLowerCase().includes(needle) ||
            item.username.toLowerCase().includes(needle) ||
            item.url.toLowerCase().includes(needle) ||
            item.tags.some((tag) => tag.toLowerCase().includes(needle))
          );
        })
        .slice(0, needle ? 6 : 3),
    [items, needle],
  );
  const matchingActions = useMemo(
    () =>
      actions
        .filter((action) => !needle || action.label.toLowerCase().includes(needle))
        .slice(0, 5),
    [actions, needle],
  );
  // With no query the palette is a command surface; typing switches it to item
  // search first, so neither group can push the other out of sight.
  const commandsFirst = needle.length === 0;
  const rows = useMemo(
    () =>
      commandsFirst
        ? [
            ...matchingActions.map((action) => ({ kind: "action" as const, action })),
            ...matchingItems.map((item) => ({ kind: "item" as const, item })),
          ]
        : [
            ...matchingItems.map((item) => ({ kind: "item" as const, item })),
            ...matchingActions.map((action) => ({ kind: "action" as const, action })),
          ],
    [commandsFirst, matchingActions, matchingItems],
  );

  useEffect(() => {
    setActive((current) => Math.min(current, Math.max(0, rows.length - 1)));
  }, [rows.length]);

  function run(index: number) {
    const row = rows[index];
    if (!row) return;
    onOpenChange(false);
    if (row.kind === "item") onSelectItem(row.item.id);
    else row.action.run();
  }

  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="overlay overlay-palette" />
        <DialogPrimitive.Content className="palette" aria-label="Command palette">
          <DialogPrimitive.Title className="sr-only">
            Command palette
          </DialogPrimitive.Title>
          <DialogPrimitive.Description className="sr-only">
            Search items, create an item, or run a vault command.
          </DialogPrimitive.Description>

          <div className="palette-input-row">
            <Search size={16} strokeWidth={1.6} aria-hidden className="palette-icon" />
            <input
              className="palette-input"
              value={query}
              onChange={(event) => {
                setQuery(event.target.value);
                setActive(0);
              }}
              placeholder="Search items or run a command"
              autoComplete="off"
              spellCheck={false}
              role="combobox"
              aria-expanded="true"
              aria-controls="palette-results"
              aria-autocomplete="list"
              aria-activedescendant={
                rows[active] ? `palette-row-${active}` : undefined
              }
              onKeyDown={(event) => {
                if (event.key === "ArrowDown") {
                  event.preventDefault();
                  setActive((current) =>
                    rows.length ? (current + 1) % rows.length : 0,
                  );
                } else if (event.key === "ArrowUp") {
                  event.preventDefault();
                  setActive((current) =>
                    rows.length ? (current - 1 + rows.length) % rows.length : 0,
                  );
                } else if (event.key === "Enter") {
                  event.preventDefault();
                  run(active);
                }
              }}
            />
            <Kbd>Esc</Kbd>
          </div>

          <div className="palette-results" id="palette-results" role="listbox" ref={listRef}>
            {rows.length === 0 ? (
              <p className="palette-empty">
                No item or command matches “{query}”.
              </p>
            ) : null}

            {matchingItems.length > 0 ? (
              <div
                className="palette-group"
                role="group"
                aria-label="Items"
                style={{ order: commandsFirst ? 2 : 1 }}
              >
                <span className="palette-group-label">Items</span>
                {matchingItems.map((item, index0) => {
                  const index = index0 + (commandsFirst ? matchingActions.length : 0);
                  return (
                    <PaletteRow
                      key={item.id}
                      id={`palette-row-${index}`}
                      item={{
                        title: item.title,
                        meta: secondaryText(item),
                        category: item.category,
                      }}
                      active={active === index}
                      glyphSize={15}
                      onActivate={() => setActive(index)}
                      onSelect={() => run(index)}
                      activeTrailing={
                        <CornerDownLeft
                          size={13}
                          aria-hidden
                          className="palette-enter"
                        />
                      }
                    />
                  );
                })}
              </div>
            ) : null}

            {matchingActions.length > 0 ? (
              <div
                className="palette-group"
                role="group"
                aria-label="Commands"
                style={{ order: commandsFirst ? 1 : 2 }}
              >
                <span className="palette-group-label">Commands</span>
                {matchingActions.map((action, offset) => {
                  const index = offset + (commandsFirst ? 0 : matchingItems.length);
                  return (
                    <PaletteRow
                      key={action.id}
                      id={`palette-row-${index}`}
                      item={{ title: action.label, glyph: action.glyph }}
                      active={active === index}
                      onActivate={() => setActive(index)}
                      onSelect={() => run(index)}
                      trailing={
                        <span className="palette-hint">{action.hint}</span>
                      }
                    />
                  );
                })}
              </div>
            ) : null}
          </div>

          <footer className="palette-foot">
            <span>
              <Kbd>↑</Kbd> <Kbd>↓</Kbd> move
            </span>
            <span>
              <Kbd>Enter</Kbd> open
            </span>
            <span className="palette-foot-seal">
              Search never reads secret values
            </span>
          </footer>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
