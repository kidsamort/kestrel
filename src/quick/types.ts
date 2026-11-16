/** Which credential a row action copies. */
export type CopyField = "username" | "password";

/** The copy flash: the item and field that was last copied successfully. */
export type CopyFlash = { itemId: string; field: CopyField };
