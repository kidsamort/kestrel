import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import Gate from "../Gate";
import { NoticeProvider } from "../ui/Toast";
import type { VaultState } from "../types";

// The gate is judged on the answers the core gives it: the bridge is mocked,
// and no test reaches the host.
const createAt = vi.fn();
const createKit = vi.fn();

vi.mock("../api", () => ({
  api: {
    helloStatus: vi.fn(),
    helloUnlock: vi.fn(),
    unlock: vi.fn(),
    create: vi.fn(),
  },
  errorText: (error: unknown) => String(error),
  hasCore: () => true,
}));

vi.mock("../lib/api-vault", () => ({
  vault: {
    location: vi.fn().mockResolvedValue({
      path: null,
      hint: null,
      initialized: false,
      locked: true,
      defaultDir: "C:\\vaults",
    }),
    openAt: vi.fn(),
    createAt: (...args: unknown[]) => createAt(...args),
    revealFolder: vi.fn(),
  },
  pickFolder: vi.fn(),
  pickVaultFile: vi.fn(),
  revealFolderPath: vi.fn(),
  vaultErrorCode: () => null,
  vaultErrorText: (error: unknown) => String(error),
  vaultFileName: (path: string) => path.split(/[\\/]/).pop() ?? path,
  vaultFilePath: (folder: string, name: string) => `${folder}\\${name}`,
}));

vi.mock("../lib/api-recovery", () => ({
  recovery: {
    create: (...args: unknown[]) => createKit(...args),
    status: vi.fn(),
    unlock: vi.fn(),
    complete: vi.fn(),
    finish: vi.fn(),
  },
}));

const LOCKED: VaultState = {
  initialized: true,
  locked: true,
  itemCount: 0,
  autolockSeconds: 300,
  clipboardClearSeconds: 30,
  vaultUuid: "",
  vaultName: "",
  vaultCount: 1,
  lockAt: null,
};

const CREATED: VaultState = {
  ...LOCKED,
  locked: false,
  vaultUuid: "vault-uuid",
  vaultName: "personal",
};

describe("Gate · recovery code at creation", () => {
  it("asks before skipping the one-time code", async () => {
    const password = "correct-horse-battery";
    createAt.mockResolvedValue(CREATED);
    createKit.mockResolvedValue({
      vaultName: "personal",
      code: "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-AAAA-C",
      createdAt: 1_700_000_000_000,
    });
    const onUnlocked = vi.fn();

    render(
      <NoticeProvider>
        <Gate state={LOCKED} lockedBy={null} onUnlocked={onUnlocked} />
      </NoticeProvider>,
    );

    fireEvent.change(
      await screen.findByLabelText("New master password"),
      { target: { value: password } },
    );
    fireEvent.change(screen.getByLabelText("Confirm master password"), {
      target: { value: password },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create vault" }));

    expect(
      await screen.findByRole("heading", { name: "Keep a way back in." }),
    ).toBeInTheDocument();
    expect(createKit).toHaveBeenCalledTimes(1);
    expect(onUnlocked).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Skip for now" }));

    // The skip is a confirmation, not an immediate exit: the vault has not
    // been handed to the shell and the warning is on screen.
    expect(onUnlocked).not.toHaveBeenCalled();
    expect(
      screen.getByText(
        /Without a code, a forgotten password means this vault cannot be opened/,
      ),
    ).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(
      screen.queryByText(/Without a code, a forgotten password/),
    ).toBeNull();
    expect(onUnlocked).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: "Skip for now" }));
    fireEvent.click(screen.getByRole("button", { name: "Skip anyway" }));

    await waitFor(() => expect(onUnlocked).toHaveBeenCalledWith(CREATED));
  });
});
