// A message for the next screen, kept in memory only: "Erase everything" clears the webview's
// storage, so it cannot live there (review P6R2-1).
let eraseIncomplete = false;

export function noteEraseIncomplete(): void {
  eraseIncomplete = true;
}

/** Whether the last erase left a file behind; the first screen to ask shows it. */
export function eraseWasIncomplete(): boolean {
  return eraseIncomplete;
}

export const ERASE_INCOMPLETE =
  "Some of Veil's files could not be deleted. The keys that protect them were destroyed, but to be sure, erase again or clear Veil's storage in your system settings.";
