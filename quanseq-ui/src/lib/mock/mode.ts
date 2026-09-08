/**
 * Showcase mode — an internal data provider that serves realistic, internally
 * consistent responses without a backend. Toggled by NEXT_PUBLIC_QUANSEQ_MODE.
 */
export const SHOWCASE_MODE = process.env.NEXT_PUBLIC_QUANSEQ_MODE === "showcase";

/** Small randomized delay so async UI states aren't visibly instant. */
export function showcaseLatency(minMs = 120, maxMs = 380): Promise<void> {
  const ms = minMs + Math.random() * (maxMs - minMs);
  return new Promise((resolve) => setTimeout(resolve, ms));
}
