import { useState } from "react";
import { errorText } from "../../api";
import { trashApi } from "../../lib/api-trash";
import type { Item } from "../../types";
import { Button } from "../../ui/Button";
import { Dialog } from "../../ui/Overlay";
import { useNotify } from "../../ui/Toast";

export default function DeleteDialog({
  item,
  open,
  onOpenChange,
  onDeleted,
}: {
  item: Item;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onDeleted: () => void;
}) {
  const notify = useNotify();
  const [deleting, setDeleting] = useState(false);

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      alert
      title={`Move “${item.title}” to the trash?`}
      description="The item leaves the vault but stays recoverable in Trash until you empty it."
      footer={
        <>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => onOpenChange(false)}
            disabled={deleting}
          >
            Keep item
          </Button>
          <Button
            variant="danger"
            size="sm"
            disabled={deleting}
            onClick={() => {
              setDeleting(true);
              trashApi
                .trash(item.id)
                .then(() => {
                  onOpenChange(false);
                  notify(`Moved “${item.title}” to the trash`, {
                    tone: "neutral",
                  });
                  onDeleted();
                })
                .catch((error) => {
                  notify("Could not move the item to the trash", {
                    detail: errorText(error),
                    tone: "danger",
                  });
                })
                .finally(() => setDeleting(false));
            }}
          >
            {deleting ? "Moving…" : "Move to trash"}
          </Button>
        </>
      }
    />
  );
}
