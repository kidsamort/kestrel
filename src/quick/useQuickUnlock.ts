import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type FormEvent,
} from "react";
import { api, errorText } from "../api";
import type { HelloStatus, VaultState } from "../types";

/**
 * Master-password state for the locked palette. It shares the core session
 * with the main window, so either door opens both.
 */
export function useQuickUnlock({
  setVault,
}: {
  setVault: (vault: VaultState) => void;
}) {
  const [password, setPassword] = useState("");
  const [unlocking, setUnlocking] = useState(false);
  const [unlockError, setUnlockError] = useState<string | null>(null);
  const [hello, setHello] = useState<HelloStatus | null>(null);
  const [helloBusy, setHelloBusy] = useState(false);
  const passwordRef = useRef<HTMLInputElement>(null);

  // The enrolment can change in the main window while this one is hidden, so
  // the status is re-read every time the palette is shown.
  const reloadHello = useCallback(() => {
    api
      .helloStatus()
      .then(setHello)
      .catch(() => setHello(null));
  }, []);

  useEffect(() => {
    reloadHello();
  }, [reloadHello]);

  const unlockWithHello = useCallback(async () => {
    if (helloBusy) return;
    setHelloBusy(true);
    setUnlockError(null);
    try {
      const next = await api.helloUnlock();
      setPassword("");
      setVault(next);
    } catch (failure) {
      setUnlockError(errorText(failure));
    } finally {
      setHelloBusy(false);
    }
  }, [helloBusy, setVault]);

  const submit = useCallback(
    async (event: FormEvent) => {
      event.preventDefault();
      if (!password || unlocking) return;
      setUnlocking(true);
      setUnlockError(null);
      try {
        const next = await api.unlock(password);
        setPassword("");
        setVault(next);
      } catch (failure) {
        setUnlockError(errorText(failure));
        passwordRef.current?.focus();
        passwordRef.current?.select();
      } finally {
        setUnlocking(false);
      }
    },
    [password, unlocking, setVault],
  );

  const reset = useCallback(() => {
    setPassword("");
    setUnlockError(null);
  }, []);

  return {
    password,
    setPassword,
    unlocking,
    unlockError,
    setUnlockError,
    passwordRef,
    submit,
    reset,
    hello,
    helloBusy,
    unlockWithHello,
    reloadHello,
  };
}
