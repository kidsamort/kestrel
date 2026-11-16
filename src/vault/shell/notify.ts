import type { Tone } from "../../ui/Toast";

/** The shell's toast contract (`useNotify`'s callable), named for use in hooks. */
export type Notify = (
  text: string,
  options?: { detail?: string; tone?: Tone },
) => void;
