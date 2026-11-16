import { useEffect, useLayoutEffect, useRef, useState } from "react";
import {
  ArrowDownWideNarrow,
  CircleX,
  CornerDownLeft,
  Pencil,
  Plus,
  Star,
  Timer,
  Trash2,
  Wand2,
} from "lucide-react";
import { metaFor, secondaryText } from "../lib/catalog";
import type { Filter, Sort } from "../lib/navigation";
import type { Category, ItemSummary } from "../types";
import { CATEGORY_LABEL } from "../types";
import { CategoryGlyph } from "../ui/CategoryGlyph";
import { Button } from "../ui/Button";
import { EmptyState } from "../ui/EmptyState";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
  Menu,
  MenuCheckboxItem,
  MenuContent,
  MenuLabel,
  MenuTrigger,
} from "../ui/Overlay";

/** Commands a row offers on right-click. */
export type RowAction = "open" | "edit" | "favorite" | "delete";

const ROW_H = 47;

export default function ItemList({
  filter,
  items,
  query,
  sort,
  selectedId,
  loading,
  onSelect,
  onQuery,
  onSort,
  onNew,
  onNewWizard,
  onClearFilter,
  onRowAction,
}: {
  filter: Filter;
  items: ItemSummary[];
  query: string;
  sort: Sort;
  selectedId: string | null;
  loading: boolean;
  onSelect: (id: string) => void;
  onQuery: (query: string) => void;
  onSort: (sort: Sort) => void;
  onNew: (category: Category) => void;
  onNewWizard: () => void;
  onClearFilter: () => void;
  /** Right-click commands for a row; omit to disable the context menu. */
  onRowAction?: (action: RowAction, item: ItemSummary) => void;
}) {
  const scroller = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewport, setViewport] = useState(600);
  const listRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const node = scroller.current;
    if (!node) return;
    const measure = () => setViewport(node.clientHeight);
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  const virtual = items.length > 80;
  const start = virtual ? Math.max(0, Math.floor(scrollTop / ROW_H) - 6) : 0;
  const end = virtual
    ? Math.min(items.length, Math.ceil((scrollTop + viewport) / ROW_H) + 6)
    : items.length;
  const visible = items.slice(start, end);
  // Leading spacer row that carries the height of the rows above the window.
  const spacer = virtual && start > 0 ? 1 : 0;

  /**
   * Scroll the row at absolute `index` into view and return it. A virtualised
   * row outside the rendered window has no node yet, so the scroller is moved
   * onto it instead; the node appears on the next render.
   */
  function revealRow(index: number) {
    // `visible` starts at `start` and, when virtualised, sits behind a spacer
    // carrying the rows above the window; both offset the DOM position.
    const row = listRef.current?.children[index - start + spacer] as
      | HTMLElement
      | undefined;
    if (row) {
      row.scrollIntoView({ block: "nearest" });
      return row;
    }
    const node = scroller.current;
    if (node) {
      node.scrollTop = Math.max(0, index * ROW_H - node.clientHeight / 2);
    }
    return undefined;
  }

  useEffect(() => {
    // Keep the selected row visible when selection changes elsewhere (palette,
    // wizard, Ctrl+E). Intentionally not re-run on scroll: a manual scroll must
    // not be pulled back to the selected row.
    if (!selectedId) return;
    const index = items.findIndex((item) => item.id === selectedId);
    if (index >= 0) revealRow(index);
    // `start`/`spacer` describe the DOM just rendered, so they are read here
    // without being watched: a scroll must not re-run this effect.
  }, [items, selectedId]);

  function focusIndex(index: number, id: string) {
    const row = revealRow(index);
    if (row) {
      row.focus();
      return;
    }
    // The node exists only after React re-renders from the reveal's scroll, so
    // wait two frames before looking it up.
    requestAnimationFrame(() =>
      requestAnimationFrame(() => {
        const next = listRef.current?.querySelector<HTMLElement>(
          `[data-item-id="${CSS.escape(id)}"]`,
        );
        next?.focus();
        next?.scrollIntoView({ block: "nearest" });
      }),
    );
  }

  function move(delta: number) {
    if (items.length === 0) return;
    const current = items.findIndex((item) => item.id === selectedId);
    const next = Math.min(
      items.length - 1,
      Math.max(0, (current === -1 ? -1 : current) + delta),
    );
    const target = items[next];
    if (!target) return;
    onSelect(target.id);
    focusIndex(next, target.id);
  }

  function onListKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      move(1);
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      move(-1);
    } else if (event.key === "Home") {
      event.preventDefault();
      const first = items[0];
      if (first) {
        onSelect(first.id);
        focusIndex(0, first.id);
      }
    } else if (event.key === "End") {
      event.preventDefault();
      const last = items[items.length - 1];
      if (last) {
        onSelect(last.id);
        focusIndex(items.length - 1, last.id);
      }
    }
  }

  const title =
    filter.mode === "all"
      ? "All items"
      : filter.mode === "favorites"
        ? "Favorites"
        : CATEGORY_LABEL[filter.category] ?? "Items";

  return (
    <section className="list" aria-label={`${title} list`}>
      <header className="list-head">
        <div className="list-heading">
          <h1 className="list-title">{title}</h1>
          <span className="list-count" aria-live="polite">
            {items.length}
          </span>
          <Button
            variant="primary"
            size="sm"
            leading={<Wand2 size={14} aria-hidden />}
            onClick={onNewWizard}
          >
            New item
          </Button>
          <span className="list-head-spacer" />
          <Menu>
            <MenuTrigger asChild>
              <button
                type="button"
                className="icon-btn list-sort"
                aria-label="Sort items"
                title="Sort items"
              >
                <ArrowDownWideNarrow size={15} strokeWidth={1.6} aria-hidden />
              </button>
            </MenuTrigger>
            <MenuContent width={190} align="end">
              <MenuLabel>Sort by</MenuLabel>
              <MenuCheckboxItem
                checked={sort === "title"}
                onCheckedChange={() => onSort("title")}
              >
                Title (A–Z)
              </MenuCheckboxItem>
              <MenuCheckboxItem
                checked={sort === "updated"}
                onCheckedChange={() => onSort("updated")}
              >
                Recently updated
              </MenuCheckboxItem>
            </MenuContent>
          </Menu>
        </div>


        {filter.mode !== "all" ? (
          <div className="filter-chip-row">
            <span className="filter-chip">
              {filter.mode === "favorites" ? (
                <Star size={12} strokeWidth={1.8} aria-hidden />
              ) : (
                <CategoryGlyph category={filter.category} size={12} />
              )}
              {title}
              <button
                type="button"
                className="filter-chip-clear"
                aria-label={`Stop filtering by ${title}`}
                onClick={onClearFilter}
              >
                <CircleX size={13} aria-hidden />
              </button>
            </span>
            <span className="filter-hint">Filtered</span>
          </div>
        ) : null}
      </header>

      <div
        className="list-scroll"
        ref={scroller}
        onScroll={(event) => setScrollTop(event.currentTarget.scrollTop)}
      >
        {loading && items.length === 0 ? (
          <div className="list-loading" aria-busy="true" aria-label="Loading items">
            {[0, 1, 2, 3].map((n) => (
              <div className="row-skeleton" key={n} style={{ opacity: 1 - n * 0.18 }} />
            ))}
          </div>
        ) : items.length === 0 ? (
          <EmptyList
            query={query}
            filter={filter}
            onClearSearch={() => onQuery("")}
            onClearFilter={onClearFilter}
            onNew={onNew}
          />
        ) : (
          <div
            className="rows"
            role="listbox"
            aria-label={`${title} items`}
            ref={listRef}
            onKeyDown={onListKeyDown}
          >
            {virtual && start > 0 ? (
              <div style={{ height: start * ROW_H }} aria-hidden />
            ) : null}
            {visible.map((item) => (
              <Row
                key={item.id}
                item={item}
                selected={item.id === selectedId}
                onSelect={() => onSelect(item.id)}
                onAction={
                  onRowAction ? (action) => onRowAction(action, item) : undefined
                }
              />
            ))}
            {virtual && end < items.length ? (
              <div
                style={{ height: (items.length - end) * ROW_H }}
                aria-hidden
              />
            ) : null}
          </div>
        )}
      </div>

      {loading && items.length > 0 ? (
        <div className="list-progress" aria-hidden="true" />
      ) : null}
    </section>
  );
}

function Row({
  item,
  selected,
  onSelect,
  onAction,
}: {
  item: ItemSummary;
  selected: boolean;
  onSelect: () => void;
  onAction?: (action: RowAction) => void;
}) {
  const row = (
    <div
      role="option"
      aria-selected={selected}
      tabIndex={selected ? 0 : -1}
      className={`row ${selected ? "is-selected" : ""}`}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect();
        }
      }}
      data-item-id={item.id}
    >
      <span className="row-glyph" aria-hidden>
        <CategoryGlyph category={item.category} size={16} />
      </span>
      <span className="row-body">
        <span className="row-title">{item.title}</span>
        <span className="row-meta">{secondaryText(item)}</span>
      </span>
      <span className="row-flags">
        {item.hasTotp ? (
          <Timer
            size={13}
            strokeWidth={1.6}
            className="row-badge"
            aria-label="Has a one-time code"
          />
        ) : null}
        {item.favorite ? (
          <Star
            size={12}
            strokeWidth={1.8}
            className="row-star"
            aria-label="Favorite"
          />
        ) : null}
      </span>
    </div>
  );

  if (!onAction) return row;

  return (
    <ContextMenu>
      <ContextMenuTrigger asChild>{row}</ContextMenuTrigger>
      <ContextMenuContent>
        <ContextMenuItem
          icon={<CornerDownLeft size={13} aria-hidden />}
          onSelect={() => onAction("open")}
        >
          Open
        </ContextMenuItem>
        <ContextMenuItem
          icon={<Pencil size={13} aria-hidden />}
          onSelect={() => onAction("edit")}
          hotkey="Ctrl E"
        >
          Edit item
        </ContextMenuItem>
        <ContextMenuItem
          icon={
            <Star
              size={13}
              aria-hidden
              fill={item.favorite ? "currentColor" : "none"}
            />
          }
          onSelect={() => onAction("favorite")}
        >
          {item.favorite ? "Remove from favorites" : "Add to favorites"}
        </ContextMenuItem>
        <ContextMenuSeparator />
        <ContextMenuItem
          icon={<Trash2 size={13} aria-hidden />}
          danger
          onSelect={() => onAction("delete")}
        >
          Move to trash
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}

function EmptyList({
  query,
  filter,
  onClearSearch,
  onClearFilter,
  onNew,
}: {
  query: string;
  filter: Filter;
  onClearSearch: () => void;
  onClearFilter: () => void;
  onNew: (category: Category) => void;
}) {
  if (query) {
    return (
      <EmptyState variant="no-match" query={query} onClear={onClearSearch} />
    );
  }

  if (filter.mode !== "all") {
    const label = filter.mode === "favorites" ? "favorites" : CATEGORY_LABEL[filter.category];
    return (
      <div className="list-empty">
        <span className="list-empty-glyph" aria-hidden>
          {filter.mode === "favorites" ? (
            <Star size={18} strokeWidth={1.4} />
          ) : (
            <CategoryGlyph category={filter.category} size={18} />
          )}
        </span>
        <h2 className="empty-title">No {label.toLowerCase()} yet.</h2>
        <p className="empty-copy">
          {filter.mode === "favorites"
            ? "Star an item from its detail view to keep it here."
            : "This filter is a category, not a folder. New items land here automatically."}
        </p>
        {filter.mode === "category" ? (
          <Button
            variant="primary"
            size="sm"
            leading={<Plus size={14} aria-hidden />}
            onClick={() => onNew(filter.category)}
          >
            Add {metaFor(filter.category).noun}
          </Button>
        ) : (
          <Button variant="secondary" size="sm" onClick={onClearFilter}>
            Show all items
          </Button>
        )}
      </div>
    );
  }

  return (
    <EmptyState
      variant="empty-vault"
      secondary={
        <>
          Start with the account you would hate to lose. Everything you add is
          sealed before it touches the disk.
        </>
      }
      actions={
        <div className="empty-actions">
          <Button
            variant="primary"
            size="sm"
            leading={<Plus size={14} aria-hidden />}
            onClick={() => onNew("login")}
          >
            Add a login
          </Button>
          <Button
            variant="secondary"
            size="sm"
            onClick={() => onNew("secureNote")}
          >
            Add a note
          </Button>
        </div>
      }
    />
  );
}
