# Theme baseline screenshots

Visual record for the light-mode theming pass on `design/light-mode`.

| Folder | Build | Theme |
|---|---|---|
| `dark-before/` | `showcase/vercel-demo` at `55b4f3a`, before any change | dark (the only theme it had) |
| `dark-after/` | `design/light-mode` | dark (saved preference) |
| `light-after/` | `design/light-mode` | light (default for first-time visitors) |

Each folder holds every route at 1440, 1024, 768 and 390 px widths:
`<route>@<width>.jpg`, where `landing` is `/` and
`route-that-does-not-exist` is the built-in 404. Portal pages were captured
signed in with the showcase data provider (`NEXT_PUBLIC_QUANSEC_MODE=showcase`);
the three login pages were captured signed out.

## How dark-mode parity was checked

Screenshots alone cannot prove parity because the showcase data carries live
timestamps. In addition, the computed colour, background, border colours, box
shadow, outline, SVG fill/stroke, opacity, font and box metrics of every
element on every route (1440 and 390 px) were recorded before and after the
change and compared element by element (10,260 elements). The only
differences:

- The active sidebar item gained `box-shadow: inset 0 0 0 1px transparent`
  (invisible in dark; it is the selected outline in light).
- The sidebar footer now holds the theme toggle beside Sign out.
- Opacity readings on animated live dots and lattice backgrounds, which differ
  only by the animation frame at capture time.

## Pre-existing dark-mode issues left unchanged

These are visible in `dark-before/` and were deliberately not changed, to keep
dark mode exactly as shipped:

- Lists using `divide-y` (alerts, API keys, SSH sessions, Zero Trust posture)
  draw bright row dividers because the hairline colour is set on the parent,
  which `divide-y` does not read. Fixed in light mode only.
- The built-in 404 page follows the operating-system colour scheme rather than
  the app theme. Fixed in light mode only.
- Some labels are 9–10 px.

This folder is review material and can be dropped before merging.
