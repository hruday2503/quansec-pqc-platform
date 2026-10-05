"use client";

import { useSyncExternalStore } from "react";
import { Moon, Sun } from "lucide-react";
import { THEME_COLOR, THEME_STORAGE_KEY, type Theme } from "@/lib/theme-script";

const listeners = new Set<() => void>();

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function readTheme(): Theme {
  return document.documentElement.getAttribute("data-theme") === "dark" ? "dark" : "light";
}

function applyTheme(next: Theme) {
  document.documentElement.setAttribute("data-theme", next);
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLOR[next]);
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, next);
  } catch {
    /* storage disabled — the choice lasts until the page is closed */
  }
  listeners.forEach((l) => l());
}

/**
 * Sun/moon switch. The theme is read from <html data-theme> after mount;
 * until then the button renders empty at its final size, so there is no
 * wrong icon during hydration and no layout shift once it appears.
 */
export function ThemeToggle({ className = "" }: { className?: string }) {
  // null on the server and during hydration.
  const theme = useSyncExternalStore<Theme | null>(subscribe, readTheme, () => null);
  const next: Theme = theme === "dark" ? "light" : "dark";
  const label = theme ? `Switch to ${next} theme` : "Switch colour theme";

  return (
    <button
      type="button"
      data-theme-toggle=""
      onClick={() => theme && applyTheme(next)}
      aria-label={label}
      title={label}
      className={`w-8 h-8 shrink-0 inline-flex items-center justify-center rounded-lg transition-colors focus-ring ${className}`}
      style={{ color: "var(--text-tertiary)", border: "1px solid var(--border-hairline)" }}
    >
      {theme === "dark" && <Sun size={15} aria-hidden />}
      {theme === "light" && <Moon size={15} aria-hidden />}
      <span className="sr-only" aria-live="polite">{theme ? `${theme === "dark" ? "Dark" : "Light"} theme active` : ""}</span>
    </button>
  );
}
