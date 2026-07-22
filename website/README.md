# ClamUI Website

Marketing site for [ClamUI](https://github.com/linx-systems/clamui), published at **https://clamui.com**.

Built with [Astro](https://astro.build) + [Tailwind CSS](https://tailwindcss.com). Static output; deploys to GitHub Pages via `.github/workflows/deploy-website.yml`.

## Local development

```bash
cd website
npm install
npm run dev        # http://localhost:4321
```

The `prebuild` / `predev` scripts copy assets (logo, screenshots) from the repo root into `public/` — there's no duplication in source control.

## Production build

```bash
npm run build
npm run preview
```

## Deploying

Pushing changes under `website/**` on `master` triggers the `deploy-website` workflow, which builds the site and publishes it to the `gh-pages` branch. GitHub Pages serves that branch at `clamui.com`.

**One-time setup (already documented in the plan):**

1. Repo → Settings → Pages: Source = *GitHub Actions*, Custom domain = `clamui.com`, Enforce HTTPS = on (enable after DNS propagates).
2. DNS at the registrar:
   - `clamui.com` A records: `185.199.108.153`, `185.199.109.153`, `185.199.110.153`, `185.199.111.153`
   - `clamui.com` AAAA records: `2606:50c0:8000::153`, `2606:50c0:8001::153`, `2606:50c0:8002::153`, `2606:50c0:8003::153`
   - `www.clamui.com` CNAME → `linx-systems.github.io`
3. `public/CNAME` contains `clamui.com` so the custom-domain setting survives deploys.

## Structure

```
website/
├── scripts/copy-assets.mjs    # syncs logo + screenshots from repo root
├── public/                    # static, unprocessed assets
├── src/
│   ├── layouts/Base.astro     # <head>, OG/Twitter, theme bootstrap
│   ├── pages/index.astro      # landing page composition
│   ├── components/            # Hero, FeatureRow, InstallTabs, ...
│   ├── content/features.ts    # feature copy
│   └── styles/global.css      # Tailwind + custom utilities
└── astro.config.mjs
```
