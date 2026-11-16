import {
  forwardRef,
  useId,
  type InputHTMLAttributes,
  type ReactNode,
  type TextareaHTMLAttributes,
} from "react";

interface TextFieldProps extends InputHTMLAttributes<HTMLInputElement> {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  trailing?: ReactNode;
  leading?: ReactNode;
  /** Hide the label visually but keep it for screen readers. */
  quietLabel?: boolean;
}

export const TextField = forwardRef<HTMLInputElement, TextFieldProps>(
  function TextField(
    { label, hint, error, trailing, leading, quietLabel, id, className, ...rest },
    ref,
  ) {
    const generated = useId();
    const inputId = id ?? generated;
    const describedBy = error
      ? `${inputId}-error`
      : hint
        ? `${inputId}-hint`
        : undefined;

    return (
      <div className={`field ${className ?? ""}`}>
        <label
          className={`field-label ${quietLabel ? "sr-only" : ""}`}
          htmlFor={inputId}
        >
          {label}
        </label>
        <div className={`input-shell ${error ? "input-invalid" : ""}`}>
          {leading ? <span className="input-leading">{leading}</span> : null}
          <input
            ref={ref}
            id={inputId}
            className="input"
            aria-invalid={error ? true : undefined}
            aria-describedby={describedBy}
            {...rest}
          />
          {trailing ? <span className="input-trailing">{trailing}</span> : null}
        </div>
        {error ? (
          <p className="field-error" id={`${inputId}-error`} role="alert">
            {error}
          </p>
        ) : hint ? (
          <p className="field-hint" id={`${inputId}-hint`}>
            {hint}
          </p>
        ) : null}
      </div>
    );
  },
);

interface TextAreaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label: string;
  hint?: ReactNode;
  quietLabel?: boolean;
}

export const TextArea = forwardRef<HTMLTextAreaElement, TextAreaProps>(
  function TextArea({ label, hint, quietLabel, id, className, ...rest }, ref) {
    const generated = useId();
    const areaId = id ?? generated;
    return (
      <div className={`field ${className ?? ""}`}>
        <label
          className={`field-label ${quietLabel ? "sr-only" : ""}`}
          htmlFor={areaId}
        >
          {label}
        </label>
        <textarea
          ref={ref}
          id={areaId}
          className="input textarea"
          aria-describedby={hint ? `${areaId}-hint` : undefined}
          {...rest}
        />
        {hint ? (
          <p className="field-hint" id={`${areaId}-hint`}>
            {hint}
          </p>
        ) : null}
      </div>
    );
  },
);
