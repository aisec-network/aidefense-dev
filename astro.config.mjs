import { defineConfig } from "astro/config";
import mdx from "@astrojs/mdx";
import sitemap from "@astrojs/sitemap";
import tailwind from "@astrojs/tailwind";
import rehypeSlug from "rehype-slug";
import rehypeExternalLinks from "rehype-external-links";
import remarkGfm from "remark-gfm";
import { siteConfig } from "./src/config/site.ts";

export default defineConfig({
  site: siteConfig.url,
  trailingSlash: "ignore",
  integrations: [
    mdx(),
    sitemap({
      changefreq: "weekly",
      priority: 0.7,
      lastmod: new Date(),
    }),
    tailwind({ applyBaseStyles: false }),
  ],
  markdown: {
    remarkPlugins: [remarkGfm],
    rehypePlugins: [
      rehypeSlug,
      [
        rehypeExternalLinks,
        {
          target: "_blank",
          rel: ["noopener", "noreferrer", "nofollow"],
          content: { type: "text", value: " ↗" },
        },
      ],
    ],
    shikiConfig: {
      theme: "github-dark-dimmed",
      wrap: true,
    },
  },
  build: {
    inlineStylesheets: "auto",
  },
  vite: {
    ssr: { noExternal: [] },
  },
});
