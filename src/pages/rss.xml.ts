import rss from "@astrojs/rss";
import { getCollection } from "astro:content";
import type { APIContext } from "astro";
import { siteConfig } from "@config/site";

export async function GET(context: APIContext) {
  const posts = await getCollection("posts", ({ data }) => !data.draft);
  return rss({
    title: siteConfig.title,
    description: siteConfig.description,
    site: context.site!,
    items: posts
      .sort((a, b) => b.data.pubDate.valueOf() - a.data.pubDate.valueOf())
      .map((post) => ({
        title: post.data.title,
        pubDate: post.data.pubDate,
        description: post.data.description,
        author: siteConfig.byline,
        link: `/posts/${post.slug}/`,
        categories: post.data.tags,
      })),
    customData: `<language>${siteConfig.language}</language>`,
  });
}
