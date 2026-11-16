import { useEffect, useState } from "react";

export interface TitlebarSlots {
  searchSlot: HTMLElement | null;
  metaSlot: HTMLElement | null;
  vaultSlot: HTMLElement | null;
}

/**
 * `App` owns the window toolbar and leaves three empty nodes in it. The shell
 * portals its primary actions into those slots instead of duplicating them in
 * the list header. They are looked up once on mount: the toolbar exists for the
 * shell's whole lifetime, and the shell itself is never mounted while locked.
 */
export function useTitlebarSlots(): TitlebarSlots {
  const [searchSlot, setSearchSlot] = useState<HTMLElement | null>(null);
  const [metaSlot, setMetaSlot] = useState<HTMLElement | null>(null);
  const [vaultSlot, setVaultSlot] = useState<HTMLElement | null>(null);

  useEffect(() => {
    setSearchSlot(document.getElementById("titlebar-search"));
    setMetaSlot(document.getElementById("titlebar-meta"));
    setVaultSlot(document.getElementById("titlebar-vault"));
  }, []);

  return { searchSlot, metaSlot, vaultSlot };
}
