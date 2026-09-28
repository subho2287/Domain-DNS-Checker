# DNS Checker

Real-time DNS, mail & security diagnostics for any domain — a fast, single-page tool
that inspects delegation, nameservers, SOA timers, MX, mail authentication (SPF / DKIM /
DMARC / MTA-STS / TLS-RPT / BIMI), HTTPS, and DNSSEC, then presents a clean, expandable
report with an optional professional PDF export.

Built to run entirely on **Cloudflare Pages** (static frontend + Pages Functions on the
Workers runtime). No servers to manage.

## Features

- **Live checks** grouped into Parent, NS, SOA, MX, Mail, Web, SSL and Security
- **DNS-over-HTTPS** (Cloudflare `1.1.1.1`) for every record lookup
- **Mail hygiene**: SPF (with `all`-policy grading and single-record validation), DKIM
  selector discovery, DMARC, MTA-STS, TLS-RPT, BIMI
- **Web / transport**: A / AAAA / CNAME, HTTPS reachability, HTTP→HTTPS redirect, HSTS,
  TLS handshake
- **Security**: CAA and DNSSEC
- **Polished UI**: HTMX + Tailwind, light/dark mode, animated section icons, collapsible
  sections, a three.js background, and a scroll-to-top control
- **Professional PDF** report (cover page, running header/footer, real vector text,
  proper pagination) generated with `pdf-lib`

## Architecture

```
public/                 Static site (served by Cloudflare Pages)
  index.html            HTMX + Tailwind UI
functions/              Cloudflare Pages Functions (Workers runtime)
  check.js              POST /check  -> HTML report fragment
  pdf.js                GET  /pdf    -> PDF report (attachment)
  _lib/
    doh.js              DNS-over-HTTPS client
    checks.js           All DNS / mail / security checks
    render.js           Pure HTML rendering
    pdf.js              pdf-lib PDF builder
wrangler.toml           Pages project config
```

The frontend posts to `/check` and fetches `/pdf`, both of which are Pages Functions —
so the same paths work locally and in production.

## Local development

Requires Node.js 18+.

```bash
npm install
npm run dev
```

This runs `wrangler pages dev public`, which serves the static site and the Functions
together (default: http://127.0.0.1:8788).

## Deploy to Cloudflare Pages via GitHub

1. Push this repository to GitHub.
2. In the Cloudflare dashboard: **Workers & Pages → Create → Pages → Connect to Git**, and
   select the repository.
3. Configure the build settings:
   - **Framework preset:** None
   - **Build command:** *(leave empty)*
   - **Build output directory:** `public`
4. Under **Settings → Functions**, ensure the **Compatibility flag** `nodejs_compat` is
   enabled (already declared in `wrangler.toml`).
5. **Save and Deploy.** Every push to the connected branch triggers a new deployment.

### Deploy from the CLI (optional)

```bash
npm run deploy        # wrangler pages deploy public
```

## Edge runtime notes

Because Cloudflare Functions run on the Workers runtime (not Node.js), two checks from a
traditional server backend are adapted:

- **TLS certificate chain / expiry / issuer** — the Workers runtime cannot inspect a peer
  certificate, so the SSL section validates the **TLS handshake** and **HSTS** instead of
  reading certificate fields.
- **SMTP (port 25) connectivity** — outbound SMTP is not available at the edge, so mail
  delivery is assessed through DNS records (MX, SPF, DKIM, DMARC, MTA-STS, TLS-RPT).

All other checks run fully at the edge via DNS-over-HTTPS and `fetch`.

## License

For educational use.
