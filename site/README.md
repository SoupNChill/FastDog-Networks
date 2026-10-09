# FastDog marketing site

Static HTML, one shared stylesheet, and a small home-only health readout. Serve `site/` at the public root; asset paths are root-absolute. No build step or external dependencies.

Routes: `/`, `/edge/`, `/domains/`, `/verdict/`, `/customers/punch-clock/`.

## Local preview

From `site/`:

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

Open `http://127.0.0.1:8000/`. HTTP previews retain the dated capture and make no health request. On HTTPS, `live.js` requests same-origin `/health` once with a four-second timeout. Only an OK response containing `ok: true` replaces the capture; failures make no status claim. Live responses omit version data. The captured output remains verbatim in the HTML.

## Operator image render step

Render `/favicon.svg` to `site/favicon-32.png` at 32×32 and `site/apple-touch-icon.png` at 180×180. Open `/og/og-source.html` at a 1200×630 viewport, wait for the bundled fonts to load, and screenshot to `site/og/og.png`. These PNGs are referenced by every marketing page and intentionally await this render step. The OG source embeds the lockup and uses relative bundled font paths.

Check the marketing pages at 390px in dark and light system themes. Logos switch through `picture`; all text colors use theme variables. There is no animation.

Pricing remains proposed planning ranges, not checkout prices. No DNS changes or deployment are part of this site refresh.

Bundled Space Grotesk and Mulish fonts retain their OFL licenses in `fonts/`.
