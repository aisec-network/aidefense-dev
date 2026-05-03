import type { APIContext } from "astro";
import { siteConfig } from "@config/site";

export async function GET(_context: APIContext) {
  const body = `User-agent: *\nAllow: /\n\nSitemap: ${siteConfig.url}/sitemap-index.xml\n`;
  return new Response(body, {
    status: 200,
    headers: { "Content-Type": "text/plain" },
  });
}
