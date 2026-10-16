import { writable } from 'svelte/store';

/** Command palette visibility, shared by the header trigger and the global shortcut. */
export const paletteOpen = writable(false);
