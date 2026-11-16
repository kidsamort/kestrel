import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import Gate from "../Gate";
import SecurityCard from "../vault/settings/SecurityCard";
import { NoticeProvider } from "../ui/Toast";
import type { HelloStatus, VaultState } from "../types";

// The renderer never talks to the host in a test: the bridge is mocked and the
// components are judged on what they do with the answers they get.
const helloStatus = vi.fn();
const helloUnlock = vi.fn();
const helloEnroll = vi.fn();
const helloDisable = vi.fn();

vi.mock("../api", () => ({
  api: {
    helloStatus: (...args: unknown[]) => helloStatus(...args),
    helloUnlock: (...args: unknown[]) => helloUnlock(...args),
    helloEnroll: (...args: unknown[]) => helloEnroll(...args),
    helloDisable: (...args: unknown[]) => helloDisable(...args),
    unlock: vi.fn(),
    create: vi.fn(),
    setAutolock: vi.fn(),
    setClipboardClear: vi.fn(),
  },
  errorText: (error: unknown) => String(error),
  hasCore: () => true,
}));

// The Gate asks where the last vault lives before it can show a door. The
// answer is fixed here: a selected file that opens locked.
vi.mock("../lib/api-vault", () => ({
  vault: {
    location: vi.fn().mockResolvedValue({
      path: "C:\\vaults\\personal.db",
      hint: null,
      initialized: true,
      locked: true,
      defaultDir: "C:\\vaults",
    }),
    openAt: vi.fn().mockResolvedValue({
      initialized: true,
      locked: true,
      itemCount: 0,
      autolockSeconds: 300,
      clipboardClearSeconds: 30,
      vaultUuid: "",
      vaultName: "",
      vaultCount: 1,
      lockAt: null,
    }),
    createAt: vi.fn(),
    revealFolder: vi.fn(),
  },
  vaultErrorCode: () => null,
  vaultErrorText: (error: unknown) => String(error),
  vaultFileName: (path: string) => path.split(/[\\/]/).pop() ?? path,
  vaultFilePath: (folder: string, name: string) => `${folder}\\${name}`,
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

const UNLOCKED: VaultState = {
  ...LOCKED,
  locked: false,
  itemCount: 3,
  vaultUuid: "vault-uuid",
  vaultName: "Personal",
};

function status(overrides: Partial<HelloStatus> = {}): HelloStatus {
  return {
    available: true,
    enrolled: false,
    mechanism: "",
    label: "",
    createdAt: null,
    detail: null,
    ...overrides,
  };
}

const ENROLLED = status({
  enrolled: true,
  mechanism: "tpm-key",
  label: "Windows Hello (TPM-backed key)",
  createdAt: 1_700_000_000_000,
});

function renderGate(onUnlocked = vi.fn()) {
  return render(
    <NoticeProvider>
      <Gate state={LOCKED} lockedBy={null} onUnlocked={onUnlocked} />
    </NoticeProvider>,
  );
}

describe("Gate · Windows Hello", () => {
  it("offers the Hello button only when the vault is enrolled", async () => {
    helloStatus.mockResolvedValue(status());
    renderGate();
    expect(
      await screen.findByRole("button", { name: "Unlock vault" }),
    ).toBeEnabled();
    await waitFor(() => expect(helloStatus).toHaveBeenCalled());
    expect(
      screen.queryByRole("button", { name: /unlock with windows hello/i }),
    ).toBeNull();
  });

  it("unlocks through the Hello command and hands the new state to the shell", async () => {
    helloStatus.mockResolvedValue(ENROLLED);
    helloUnlock.mockResolvedValue(UNLOCKED);
    const onUnlocked = vi.fn();
    renderGate(onUnlocked);

    const button = await screen.findByRole("button", {
      name: /unlock with windows hello/i,
    });
    fireEvent.click(button);

    await waitFor(() => expect(onUnlocked).toHaveBeenCalledWith(UNLOCKED));
    // No password was typed: the enrollment is the credential.
    expect(helloUnlock).toHaveBeenCalledTimes(1);
  });

  it("shows the core's own words when the prompt is cancelled", async () => {
    helloStatus.mockResolvedValue(ENROLLED);
    helloUnlock.mockRejectedValue("Windows Hello was cancelled");
    renderGate();

    fireEvent.click(
      await screen.findByRole("button", {
        name: /unlock with windows hello/i,
      }),
    );

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "Windows Hello was cancelled",
    );
    expect(screen.getByRole("button", { name: "Unlock vault" })).toBeEnabled();
  });

  it("hides the button and explains itself when Hello is enrolled but unusable", async () => {
    helloStatus.mockResolvedValue(
      status({
        ...ENROLLED,
        available: false,
        detail:
          "Windows Hello unlock is not available: the TPM is not ready (disabled, cleared or still starting)",
      }),
    );
    renderGate();

    expect(await screen.findByText(/enrolled but unavailable/)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: /unlock with windows hello/i }),
    ).toBeNull();
    expect(screen.getByRole("button", { name: "Unlock vault" })).toBeEnabled();
  });

  it("keeps the password door usable when the status call fails", async () => {
    helloStatus.mockRejectedValue("core unreachable");
    renderGate();
    await waitFor(() => expect(helloStatus).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /windows hello/i })).toBeNull();
    expect(screen.getByLabelText("Master password")).toBeInTheDocument();
  });
});

describe("Settings · Windows Hello row", () => {
  function renderCard(onState = vi.fn()) {
    return render(
      <NoticeProvider>
        <SecurityCard state={UNLOCKED} onState={onState} onLock={vi.fn()} />
      </NoticeProvider>,
    );
  }

  it("enables enrolment and reports the mechanism", async () => {
    helloStatus.mockResolvedValue(status());
    helloEnroll.mockResolvedValue(ENROLLED);
    renderCard();

    const enable = await screen.findByRole("button", {
      name: /enable hello unlock/i,
    });
    fireEvent.click(enable);

    await waitFor(() => expect(helloEnroll).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByRole("button", { name: /remove hello unlock/i }),
    ).toBeInTheDocument();
    expect(screen.getByText(/tpm-key/)).toBeInTheDocument();
    expect(screen.getByText(/master password still opens the vault/)).toBeInTheDocument();
  });

  it("removes enrolment", async () => {
    helloStatus.mockResolvedValue(ENROLLED);
    helloDisable.mockResolvedValue(status());
    renderCard();

    fireEvent.click(
      await screen.findByRole("button", { name: /remove hello unlock/i }),
    );

    await waitFor(() => expect(helloDisable).toHaveBeenCalledTimes(1));
    expect(
      await screen.findByRole("button", { name: /enable hello unlock/i }),
    ).toBeInTheDocument();
  });

  it("does not offer enrolment when the machine cannot use Hello", async () => {
    helloStatus.mockResolvedValue(
      status({
        available: false,
        detail: "Windows Hello unlock is not available: the TPM is not ready",
      }),
    );
    renderCard();

    const enable = await screen.findByRole("button", {
      name: /enable hello unlock/i,
    });
    expect(enable).toBeDisabled();
    expect(screen.getByText(/TPM is not ready/)).toBeInTheDocument();
  });
});
