import { el } from "./dom.js";

/** Getting something out of the page: onto the clipboard, or into a file. */

/** Copies `text`, and says so on the button that asked for a moment. */
export async function copyText(text: string, button: HTMLButtonElement): Promise<void> {
  const label = button.textContent ?? "";
  try {
    // Absent outside a secure context (plain http to anything but localhost).
    await navigator.clipboard.writeText(text);
    button.textContent = "copied";
  } catch {
    button.textContent = "copy failed";
  }
  setTimeout(() => {
    button.textContent = label;
  }, 1400);
}

export function download(text: string, filename: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const anchor = el("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
