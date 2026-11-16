import { Copy, History, MoreHorizontal, Pencil, Star, Trash2 } from "lucide-react";
import type { CopyApi } from "../../lib/copy";
import type { Item } from "../../types";
import { CategoryGlyph } from "../../ui/CategoryGlyph";
import { Menu, MenuContent, MenuItem, MenuSeparator, MenuTrigger } from "../../ui/Overlay";
import { Tip } from "../../ui/Tooltip";

export default function DetailHeader({
  item,
  label,
  onCopyField,
  onEdit,
  onFavorite,
  onHistory,
  onRequestDelete,
}: {
  item: Item;
  label: string | undefined;
  onCopyField: CopyApi["copyField"];
  onEdit: () => void;
  onFavorite: (favorite: boolean) => void;
  onHistory: () => void;
  onRequestDelete: () => void;
}) {
  return (
    <header className="detail-head">
      <div className="detail-head-inner">
      <span className="detail-glyph" aria-hidden>
        <CategoryGlyph category={item.category} size={22} />
      </span>
      <div className="detail-heading">
        <span className="eyebrow">{label}</span>
        <h1 className="detail-title" id="detail-title">
          {item.title}
        </h1>
      </div>
      <div className="detail-actions">
        <Tip label={item.favorite ? "Remove from favorites" : "Add to favorites"}>
          <button
            type="button"
            className={`icon-btn ${item.favorite ? "is-starred" : ""}`}
            aria-pressed={item.favorite}
            aria-label={item.favorite ? "Remove from favorites" : "Add to favorites"}
            onClick={() => onFavorite(!item.favorite)}
          >
            <Star
              size={15}
              strokeWidth={1.6}
              fill={item.favorite ? "currentColor" : "none"}
              aria-hidden
            />
          </button>
        </Tip>
        <Menu>
          <MenuTrigger asChild>
            <button
              type="button"
              className="icon-btn"
              aria-label="More actions"
            >
              <MoreHorizontal size={16} strokeWidth={1.6} aria-hidden />
            </button>
          </MenuTrigger>
          <MenuContent width={220}>
            <MenuItem
              icon={<Copy size={13} aria-hidden />}
              onSelect={() => onCopyField(item.id, "__notes", "notes")}
              disabled={!item.notes}
            >
              Copy notes
            </MenuItem>
            <MenuItem
              icon={<Pencil size={13} aria-hidden />}
              onSelect={onEdit}
              hotkey="Ctrl E"
            >
              Edit item
            </MenuItem>
            <MenuItem
              icon={<History size={13} aria-hidden />}
              onSelect={onHistory}
            >
              History
            </MenuItem>
            <MenuItem
              icon={
                <Star
                  size={13}
                  aria-hidden
                  fill={item.favorite ? "currentColor" : "none"}
                />
              }
              onSelect={() => onFavorite(!item.favorite)}
            >
              {item.favorite ? "Remove from favorites" : "Add to favorites"}
            </MenuItem>
            <MenuSeparator />
            <MenuItem
              icon={<Trash2 size={13} aria-hidden />}
              danger
              onSelect={onRequestDelete}
            >
              Delete item
            </MenuItem>
          </MenuContent>
        </Menu>
      </div>
      </div>
    </header>
  );
}
