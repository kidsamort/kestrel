/**
 * The printable half of the recovery kit. It exists only while a freshly minted
 * code is still in memory (`kit !== null`): on screen it is hidden, and when the
 * user prints, `.recovery-sheet` is the only thing that reaches paper.
 *
 * Nothing here persists the code. There is no file, no download and no copy
 * button: the point of the sheet is that the secret leaves the machine on paper
 * and only in the user's hands.
 */
import type { RecoveryKit } from "../lib/api-recovery";

/** `XXXX-XXXX-…-XXXX-C`, already formatted by the core. */
export function RecoveryCode({ code }: { code: string }) {
  return <code className="recovery-code">{code}</code>;
}

export default function RecoveryPrint({ kit }: { kit: RecoveryKit }) {
  const date = new Date(kit.createdAt).toLocaleDateString(undefined, {
    year: "numeric",
    month: "long",
    day: "numeric",
  });

  return (
    <article className="recovery-sheet" aria-hidden="true">
      <header className="recovery-sheet-head">
        <p className="recovery-sheet-brand">Kestrel recovery kit</p>
        <h1 className="recovery-sheet-title">{kit.vaultName}</h1>
        <p className="recovery-sheet-date">Created {date}</p>
      </header>

      <p className="recovery-sheet-label">Recovery code</p>
      <RecoveryCode code={kit.code} />

      <ol className="recovery-sheet-steps">
        <li>
          This code alone opens the vault. No master password is needed, and
          nothing else on this sheet has to be kept with it.
        </li>
        <li>
          To use it: unlock the vault, choose “I have a recovery code”, enter the
          code, then set a new master password. The vault asks for the new
          password before anything can be read.
        </li>
        <li>
          The code is single use. Using it replaces it with a new one, which the
          app shows once — print that one too.
        </li>
      </ol>

      <p className="recovery-sheet-warning">
        Store this sheet offline: a safe, a filing cabinet, a sealed envelope —
        anywhere that is not this computer, a cloud drive or a photo roll. Anyone
        who reads it can open the vault.
      </p>
      <p className="recovery-sheet-foot">
        Kestrel · local vault · this sheet is the only copy of this code
      </p>
    </article>
  );
}
