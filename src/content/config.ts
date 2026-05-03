import { defineCollection, z } from "astro:content";

const posts = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string().max(120),
    description: z.string().max(280),
    pubDate: z.coerce.date(),
    updatedDate: z.coerce.date().optional(),
    author: z.string().default("Editorial"),
    tags: z.array(z.string()).default([]),
    category: z.string().optional(),
    heroImage: z.string().optional(),
    heroAlt: z.string().optional(),
    draft: z.boolean().default(false),
    canonical: z.string().url().optional(),
    sources: z
      .array(
        z.object({
          title: z.string(),
          url: z.string().url(),
        })
      )
      .default([]),
    affiliateDisclosure: z.boolean().default(false),
    schema: z
      .object({
        type: z.enum(["Article", "NewsArticle", "TechArticle", "BlogPosting"]).default("Article"),
      })
      .default({}),
  }),
});

const pages = defineCollection({
  type: "content",
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    updatedDate: z.coerce.date().optional(),
    layout: z.enum(["default", "wide"]).default("default"),
  }),
});

export const collections = { posts, pages };
