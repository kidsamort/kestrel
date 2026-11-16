import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as ContextPrimitive from "@radix-ui/react-context-menu";
import * as MenuPrimitive from "@radix-ui/react-dropdown-menu";
import type { ReactNode } from "react";
import { Check, ChevronRight } from "lucide-react";

/* ---------------------------------------------------------------- dialogs */

export function Dialog({
  open,
  onOpenChange,
  title,
  description,
  children,
  footer,
  width = 420,
  alert = false,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  description?: ReactNode;
  children?: ReactNode;
  footer?: ReactNode;
  width?: number;
  alert?: boolean;
}) {
  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="overlay" />
        <DialogPrimitive.Content
          className="dialog"
          style={{ width }}
          role={alert ? "alertdialog" : "dialog"}
        >
          <DialogPrimitive.Title className="dialog-title">
            {title}
          </DialogPrimitive.Title>
          {description ? (
            <DialogPrimitive.Description className="dialog-desc">
              {description}
            </DialogPrimitive.Description>
          ) : null}
          {children ? <div className="dialog-body">{children}</div> : null}
          {footer ? <div className="dialog-footer">{footer}</div> : null}
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

/* ------------------------------------------------------------------ menus */

export const Menu = MenuPrimitive.Root;
export const MenuTrigger = MenuPrimitive.Trigger;

export function MenuContent({
  children,
  align = "end",
  side = "bottom",
  width,
  className,
}: {
  children: ReactNode;
  align?: "start" | "center" | "end";
  side?: "top" | "bottom";
  width?: number;
  className?: string;
}) {
  return (
    <MenuPrimitive.Portal>
      <MenuPrimitive.Content
        className={`menu ${className ?? ""}`}
        align={align}
        side={side}
        sideOffset={6}
        style={width ? { minWidth: width } : undefined}
      >
        {children}
      </MenuPrimitive.Content>
    </MenuPrimitive.Portal>
  );
}

export function MenuLabel({ children }: { children: ReactNode }) {
  return <MenuPrimitive.Label className="menu-label">{children}</MenuPrimitive.Label>;
}

export function MenuItem({
  children,
  onSelect,
  danger = false,
  hotkey,
  disabled = false,
  icon,
}: {
  children: ReactNode;
  onSelect: () => void;
  danger?: boolean;
  hotkey?: string;
  disabled?: boolean;
  icon?: ReactNode;
}) {
  return (
    <MenuPrimitive.Item
      className={`menu-item ${danger ? "menu-item-danger" : ""}`}
      onSelect={onSelect}
      disabled={disabled}
    >
      <span className="menu-icon">{icon}</span>
      <span className="menu-text">{children}</span>
      {hotkey ? <span className="menu-hotkey">{hotkey}</span> : null}
    </MenuPrimitive.Item>
  );
}

export function MenuSeparator() {
  return <MenuPrimitive.Separator className="menu-sep" />;
}

/* ---------------------------------------------------------- context menus */

export const ContextMenu = ContextPrimitive.Root;
export const ContextMenuTrigger = ContextPrimitive.Trigger;

/**
 * Right-click menu. It shares the dropdown's classes on purpose: one visual
 * language for "commands about this row", however it was opened.
 */
export function ContextMenuContent({
  children,
  width = 220,
}: {
  children: ReactNode;
  width?: number;
}) {
  return (
    <ContextPrimitive.Portal>
      <ContextPrimitive.Content
        className="menu"
        style={width ? { minWidth: width } : undefined}
      >
        {children}
      </ContextPrimitive.Content>
    </ContextPrimitive.Portal>
  );
}

export function ContextMenuItem({
  children,
  onSelect,
  danger = false,
  hotkey,
  disabled = false,
  icon,
}: {
  children: ReactNode;
  onSelect: () => void;
  danger?: boolean;
  hotkey?: string;
  disabled?: boolean;
  icon?: ReactNode;
}) {
  return (
    <ContextPrimitive.Item
      className={`menu-item ${danger ? "menu-item-danger" : ""}`}
      onSelect={onSelect}
      disabled={disabled}
    >
      <span className="menu-icon">{icon}</span>
      <span className="menu-text">{children}</span>
      {hotkey ? <span className="menu-hotkey">{hotkey}</span> : null}
    </ContextPrimitive.Item>
  );
}

export function ContextMenuSeparator() {
  return <ContextPrimitive.Separator className="menu-sep" />;
}

export function MenuSub({
  label,
  icon,
  children,
}: {
  label: string;
  icon?: ReactNode;
  children: ReactNode;
}) {
  return (
    <MenuPrimitive.Sub>
      <MenuPrimitive.SubTrigger className="menu-item">
        <span className="menu-icon">{icon}</span>
        <span className="menu-text">{label}</span>
        <ChevronRight size={13} className="menu-chevron" aria-hidden />
      </MenuPrimitive.SubTrigger>
      <MenuPrimitive.Portal>
        <MenuPrimitive.SubContent className="menu" sideOffset={4}>
          {children}
        </MenuPrimitive.SubContent>
      </MenuPrimitive.Portal>
    </MenuPrimitive.Sub>
  );
}

export function MenuCheckboxItem({
  children,
  checked,
  onCheckedChange,
}: {
  children: ReactNode;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}) {
  return (
    <MenuPrimitive.CheckboxItem
      className="menu-item"
      checked={checked}
      onCheckedChange={onCheckedChange}
    >
      <span className="menu-icon">
        {checked ? <Check size={13} aria-hidden /> : null}
      </span>
      <span className="menu-text">{children}</span>
    </MenuPrimitive.CheckboxItem>
  );
}
