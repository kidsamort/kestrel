import { forwardRef, type ButtonHTMLAttributes, type ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "quiet";
type Size = "sm" | "md" | "lg";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  /** Square icon-only button; `label` becomes the accessible name. */
  iconOnly?: boolean;
  label?: string;
  leading?: ReactNode;
  trailing?: ReactNode;
  block?: boolean;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  function Button(
    {
      variant = "secondary",
      size = "md",
      iconOnly = false,
      label,
      leading,
      trailing,
      block = false,
      className,
      children,
      type = "button",
      ...rest
    },
    ref,
  ) {
    const classes = [
      "btn",
      `btn-${variant}`,
      `btn-${size}`,
      iconOnly ? "btn-icon" : "",
      block ? "btn-block" : "",
      className ?? "",
    ]
      .filter(Boolean)
      .join(" ");

    return (
      <button
        ref={ref}
        type={type}
        className={classes}
        aria-label={iconOnly ? (label ?? undefined) : undefined}
        title={iconOnly ? undefined : undefined}
        {...rest}
      >
        {leading}
        {children}
        {trailing}
      </button>
    );
  },
);
