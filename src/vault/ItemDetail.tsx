import { useEffect, useState } from "react";
import { Check, Copy, ExternalLink, Globe, LockKeyhole } from "lucide-react";
import AttachmentsSection from "./AttachmentsSection";
import { api, errorText } from "../api";
import { metaFor } from "../lib/catalog";
import type { CopyApi } from "../lib/copy";
import { relativeTime } from "../lib/format";
import type { Item } from "../types";
import { CategoryGlyph } from "../ui/CategoryGlyph";
import { useNotify } from "../ui/Toast";
import { Tip } from "../ui/Tooltip";
import DeleteDialog from "./detail/DeleteDialog";
import DetailHeader from "./detail/DetailHeader";
import FieldsCard from "./detail/FieldsCard";
import NotesCard from "./detail/NotesCard";
import PasskeysBlock from "./detail/PasskeysBlock";
import TotpCard from "./detail/TotpCard";

export default function ItemDetail({
  item,
  loading,
  copiedKey,
  onCopyField,
  onCopyText,
  onEdit,
  onFavorite,
  onDelete,
  onSearchTag,
  onHistory,
}: {
  item: Item | null;
  loading: boolean;
  copiedKey: string | null;
  onCopyField: CopyApi["copyField"];
  onCopyText: CopyApi["copyText"];
  onEdit: () => void;
  onFavorite: (favorite: boolean) => void;
  onDelete: () => void;
  onSearchTag: (tag: string) => void;
  onHistory: () => void;
}) {
  const notify = useNotify();
  const [confirmOpen, setConfirmOpen] = useState(false);

  useEffect(() => {
    setConfirmOpen(false);
  }, [item?.id]);

  const meta = item ? metaFor(item.category) : null;
  const notesLed = item?.category === "secureNote" || item?.category === "document";

  if (!item) {
    return (
      <section className="detail detail-idle" aria-label="Item detail">
        <div className="detail-idle-inner">
          <span className="detail-idle-glyph" aria-hidden>
            <CategoryGlyph category="login" size={22} />
          </span>
          <h1 className="idle-title">
            {loading ? "Opening the item…" : "Nothing opened."}
          </h1>
          {!loading ? (
            <>
              <p className="idle-copy">
                Pick an item on the left. Everything in this pane is decrypted
                for as long as it is open.
              </p>
              <p className="idle-hint">
                <kbd className="kbd">↑</kbd> <kbd className="kbd">↓</kbd> to move
                · <kbd className="kbd">Ctrl</kbd> <kbd className="kbd">K</kbd> to
                search everything
              </p>
            </>
          ) : null}
        </div>
      </section>
    );
  }

  return (
    <section className="detail" aria-label={`${item.title} details`}>
      <DetailHeader
        item={item}
        label={meta?.label}
        onCopyField={onCopyField}
        onEdit={onEdit}
        onFavorite={onFavorite}
        onHistory={onHistory}
        onRequestDelete={() => setConfirmOpen(true)}
      />

      <div className="detail-scroll">
        {item.totpSecret ? (
          <TotpCard
            itemId={item.id}
            copiedKey={copiedKey}
            onCopy={onCopyText}
          />
        ) : null}

        {notesLed && item.notes ? (
          <NotesCard
            title={item.category === "secureNote" ? "Note" : "Document"}
            notes={item.notes}
          />
        ) : null}

        <FieldsCard
          itemId={item.id}
          fields={item.fields}
          copiedKey={copiedKey}
          onCopy={onCopyField}
        />

        {/* Passkeys belong to logins: a credential is bound to an rpId, and
            the other 17 categories have no site to register against. */}
        {item.category === "login" ? (
          <PasskeysBlock
            itemId={item.id}
            onError={(message) =>
              notify("Passkeys", { detail: message, tone: "danger" })
            }
          />
        ) : null}

        <AttachmentsSection
          itemId={item.id}
          onError={(message) =>
            notify("Attachments", { detail: message, tone: "danger" })
          }
        />

        {item.urls.length > 0 ? (
          <section className="block">
            <h2 className="block-title">
              Websites <span className="block-count">{item.urls.length}</span>
            </h2>
            <div className="link-list">
              {item.urls.map((url) => (
                <div className="link-row" key={url}>
                  <Globe size={14} strokeWidth={1.5} aria-hidden className="link-glyph" />
                  <span className="link-value">{url}</span>
                  <Tip label="Open in browser">
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Open ${url} in the browser`}
                      onClick={() => {
                        api.openUrl(url).catch((error) =>
                          notify("Could not open the link", {
                            detail: errorText(error),
                            tone: "danger",
                          }),
                        );
                      }}
                    >
                      <ExternalLink size={14} strokeWidth={1.6} aria-hidden />
                    </button>
                  </Tip>
                  <Tip label="Copy link">
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`Copy link ${url}`}
                      onClick={() => onCopyText(url, "website")}
                    >
                      {copiedKey === `text:website` ? (
                        <Check size={14} className="copy-done" aria-hidden />
                      ) : (
                        <Copy size={14} strokeWidth={1.6} aria-hidden />
                      )}
                    </button>
                  </Tip>
                </div>
              ))}
            </div>
            <p className="block-note">
              Opening a link hands it to the system browser; the core only
              accepts http and https.
            </p>
          </section>
        ) : null}

        {item.tags.length > 0 ? (
          <section className="block">
            <h2 className="block-title">Tags</h2>
            <div className="tag-row">
              {item.tags.map((tag) => (
                <button
                  type="button"
                  key={tag}
                  className="tag"
                  onClick={() => onSearchTag(tag)}
                  aria-label={`Search for tag ${tag}`}
                >
                  {tag}
                </button>
              ))}
            </div>
          </section>
        ) : null}

        {item.notes && !notesLed ? (
          <NotesCard title="Notes" notes={item.notes} />
        ) : null}

      </div>

      <footer className="detail-foot">
        <span>
          Created {relativeTime(item.createdAt)} · Last edit{" "}
          {relativeTime(item.updatedAt)}
        </span>
        <span className="foot-seal">
          <LockKeyhole size={11} aria-hidden /> Sealed with the vault key
        </span>
      </footer>

      <DeleteDialog
        item={item}
        open={confirmOpen}
        onOpenChange={setConfirmOpen}
        onDeleted={onDelete}
      />
    </section>
  );
}
