# TomPanel Identity

- `v1/` — the earlier AI-generated reference board (archive).
- `v2/` — the current production vector system.

The v2 mark, palette, and type choices are all derived from the product
itself: the UI's monospace display font, its ink and signal-blue accents, and
its green "healthy" state.

## The mark

A rounded-square frame (the audited boundary) containing a bold monospace
**T** — one server tower — punctuated by a green **healthz dot**. Read as
"T.": every operation ends in a verified green state.

- The dot's right edge locks to the crossbar's right edge.
- The dot's bottom locks to the stem's baseline.
- All geometry sits on a 28-unit grid (512 viewBox); frame radius 96, stroke 52.

## Files

| File | Use |
| --- | --- |
| `v2/logo-mark.svg` | Primary mark on light backgrounds (blue frame, ink T) |
| `v2/logo-mark-solid.svg` | App icon / favicon / sizes ≤ 32 px (solid ink chip) |
| `v2/logo-mark-on-dark.svg` | Mark on dark backgrounds (paper frame, bright dot) |
| `v2/logo-glyph-mono.svg` | Single-color uses; inherits `currentColor` |
| `v2/wordmark.svg` | `tompanel` + green period, mono lowercase |
| `v2/lockup-horizontal.svg` | Mark + wordmark, horizontal |
| `v2/brandkit-board.svg` / `.png` | 9-panel identity overview |

## Palette (matches `web/static/app.css`)

| Token | Hex | Role |
| --- | --- | --- |
| Paper | `#F7F8FA` | Page background |
| Ink | `#202633` | Letterform, text |
| Signal | `#2563D9` | Frame, interactive accent |
| Ops Green | `#147A4B` | Healthz dot on light (`#2FBF71` on dark) |
| Rule | `#DDE1E8` | Hairlines, borders |
| Warn / Bad | `#93620B` / `#B4232C` | State colors, UI only |

## Typography

- **Display / wordmark:** the UI's monospace stack (`ui-monospace`, Menlo,
  Cascadia Mono…). The wordmark is lowercase `tompanel` — the CLI binary name —
  with a green period.
- **Body:** Inter (falls back to system sans).

## Usage rules

- Minimum size: 24 px for the frame mark; 16 px with the solid chip.
- Clear space around the mark ≥ the dot's diameter.
- Never recolor the dot anything but Ops Green; it is the brand's one
  semantic gesture ("healthy").
- On dark surfaces use `logo-mark-on-dark.svg`; do not put the blue-frame
  primary mark on ink backgrounds.

## Rendering the board

```
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --disable-gpu --hide-scrollbars --window-size=2560x1920 \
  --screenshot=brandkit-board.png brandkit-board.svg
```
