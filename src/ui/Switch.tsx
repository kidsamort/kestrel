import * as SwitchPrimitive from "@radix-ui/react-switch";

export function Switch({
  checked,
  onCheckedChange,
  label,
  disabled,
}: {
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
  /** Accessible name; the visible label is rendered by the caller. */
  label: string;
  disabled?: boolean;
}) {
  return (
    <SwitchPrimitive.Root
      className="switch"
      checked={checked}
      onCheckedChange={onCheckedChange}
      aria-label={label}
      disabled={disabled}
    >
      <SwitchPrimitive.Thumb className="switch-thumb" />
    </SwitchPrimitive.Root>
  );
}
