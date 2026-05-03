# Astro base template

Reusable template for all 6 portfolio sites. Each site is a clone with a different `src/config/site.ts`.

## Local dev

```
npm install
npm run dev
```

## Build

```
npm run build
```

Output goes to `dist/`. Cloudflare Pages auto-deploys this on push to `main`.

## Customizing per site

Edit `src/config/site.ts` only. That file is the single source of truth for:

- Domain, URL, title, tagline, description
- Pseudonymous byline
- Theme accent colors
- Newsletter provider + embed URL
- Sister-site cross-links
- Email addresses (for routing via Cloudflare Email Routing)
- Analytics IDs

## Content

`src/content/posts/*.md` or `*.mdx` — blog posts.
`src/content/pages/*.md` — standalone pages (about, disclosure, etc.).

Required frontmatter for posts: `title`, `description`, `pubDate`. See `src/content/config.ts` for the full schema.

## Cloudflare Pages

Connect this repo to Cloudflare Pages. Build command: `npm run build`. Output dir: `dist`.
