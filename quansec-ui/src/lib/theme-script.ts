/**
 * Theme constants shared by the root layout (server) and the toggle (client).
 * No "use client" here: the layout inlines THEME_BOOT_SCRIPT into <head>.
 */

export type Theme = "light" | "dark";

export const THEME_STORAGE_KEY = "quansec-theme";

/** First-time visitors get light; a saved choice always wins. The OS setting is not consulted. */
export const DEFAULT_THEME: Theme = "light";

/** Browser chrome colour per theme, matching --bg-void. */
export const THEME_COLOR: Record<Theme, string> = { light: "#F6F8FA", dark: "#0a0c10" };

/**
 * Runs in <head> before first paint so a saved theme never flashes the other
 * one. try/catch because storage can be unavailable (private windows).
 */
export const THEME_BOOT_SCRIPT = `(function(){var d=document.documentElement,t=${JSON.stringify(DEFAULT_THEME)};try{var s=localStorage.getItem(${JSON.stringify(THEME_STORAGE_KEY)});if(s==="light"||s==="dark")t=s;}catch(e){}d.setAttribute("data-theme",t);var m=document.querySelector('meta[name="theme-color"]');if(m)m.setAttribute("content",t==="dark"?${JSON.stringify(THEME_COLOR.dark)}:${JSON.stringify(THEME_COLOR.light)});})();`;
