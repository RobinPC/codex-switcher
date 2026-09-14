import type { ImportAccountsSummary } from "../types";

export type FileSource = string | File;

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function invokeBackend<T>(
  command: string,
  args?: Record<string, unknown>
): Promise<T> {
  if (!isTauriRuntime()) {
    throw new Error("Codex Switcher backend access is available only in the desktop app");
  }

  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(command, args);
}

export async function openExternalUrl(url: string): Promise<void> {
  if (isTauriRuntime()) {
    const { openUrl } = await import("@tauri-apps/plugin-opener");
    await openUrl(url);
    return;
  }

  window.open(url, "_blank", "noopener,noreferrer");
}

export async function pickAuthJsonFile(): Promise<FileSource | null> {
  if (isTauriRuntime()) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      multiple: false,
      filters: [{ name: "JSON", extensions: ["json"] }],
      title: "Select auth.json file",
    });

    if (!selected || Array.isArray(selected)) return null;
    return selected;
  }

  return pickBrowserFile(".json,application/json");
}

export async function importFullBackupFile(): Promise<ImportAccountsSummary | null> {
  if (isTauriRuntime()) {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({
      multiple: false,
      title: "Import Full Encrypted Account Config",
      filters: [{ name: "Codex Switcher Full Backup", extensions: ["cswf"] }],
    });

    if (!selected || Array.isArray(selected)) return null;
    return invokeBackend<ImportAccountsSummary>("import_accounts_full_encrypted_file", {
      path: selected,
    });
  }

  const selected = await pickBrowserFile(".cswf,application/octet-stream");
  if (!selected) return null;

  const contentsBase64 = await fileToBase64(selected);
  return invokeBackend<ImportAccountsSummary>("import_accounts_full_encrypted_bytes", {
    contentsBase64,
  });
}
export function describeFileSource(source: FileSource | null): string {
  if (!source) return "No file selected";
  return typeof source === "string" ? source : source.name;
}

async function fileToBase64(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";

  for (let index = 0; index < bytes.length; index += 0x8000) {
    const chunk = bytes.subarray(index, index + 0x8000);
    binary += String.fromCharCode(...chunk);
  }

  return window.btoa(binary);
}

async function pickBrowserFile(accept: string): Promise<File | null> {
  return new Promise((resolve) => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = accept;
    input.style.display = "none";
    let settled = false;

    const finish = (file: File | null) => {
      if (settled) return;
      settled = true;
      window.removeEventListener("focus", handleWindowFocus);
      input.remove();
      resolve(file);
    };

    const handleWindowFocus = () => {
      window.setTimeout(() => {
        finish(input.files?.[0] ?? null);
      }, 0);
    };

    input.addEventListener(
      "change",
      () => {
        finish(input.files?.[0] ?? null);
      },
      { once: true }
    );

    document.body.appendChild(input);
    window.addEventListener("focus", handleWindowFocus, { once: true });
    input.click();
  });
}
