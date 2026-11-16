import { useState } from "react";
import { X } from "lucide-react";

export function TagEditor({
  tags,
  onChange,
}: {
  tags: string[];
  onChange: (tags: string[]) => void;
}) {
  const [draft, setDraft] = useState("");

  function commit() {
    const value = draft.trim().replace(/,$/, "");
    if (!value) return;
    if (!tags.some((tag) => tag.toLowerCase() === value.toLowerCase())) {
      onChange([...tags, value]);
    }
    setDraft("");
  }

  return (
    <div className="tag-editor">
      {tags.map((tag) => (
        <span className="tag" key={tag}>
          {tag}
          <button
            type="button"
            className="tag-remove"
            aria-label={`Remove tag ${tag}`}
            onClick={() => onChange(tags.filter((value) => value !== tag))}
          >
            <X size={11} aria-hidden />
          </button>
        </span>
      ))}
      <input
        className="tag-input"
        value={draft}
        placeholder={tags.length ? "Add tag" : "work, personal, …"}
        aria-label="Add tag"
        onChange={(event) => setDraft(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === ",") {
            event.preventDefault();
            commit();
          } else if (event.key === "Backspace" && !draft && tags.length) {
            onChange(tags.slice(0, -1));
          }
        }}
        onBlur={commit}
      />
    </div>
  );
}
