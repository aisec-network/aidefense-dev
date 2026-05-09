/**
 * schema.ts — structured-data helpers for schema.org enrichment
 *
 * Functions here are pure (no Astro imports) so they can be tested
 * independently and imported from any layout.
 */

// ---------------------------------------------------------------------------
// FAQPage
// ---------------------------------------------------------------------------

/**
 * Parse FAQ Q/A pairs from markdown content and return a JSON-LD FAQPage
 * string, or null if no FAQ section is found.
 *
 * Supported question patterns (inside a ## FAQ or ## Frequently Asked section):
 *   ### Q: What is...
 *   **Q:** What is...
 *   **Question:** What is...
 */
export function buildFAQSchema(content: string): string | null {
  // Only proceed if there's a FAQ heading
  if (!/^##\s+(FAQ|Frequently Asked)/im.test(content)) return null;

  const pairs: Array<{ question: string; answer: string }> = [];

  // Split on question markers — handles ### Q:, **Q:**, **Question:**
  const questionRe =
    /(?:^###\s+(?:Q(?:uestion)?:|)[ \t]*(.+)|^\*\*(?:Q(?:uestion)?:)\*\*[ \t]*(.+))/gim;

  let match: RegExpExecArray | null;
  const matches: Array<{ index: number; question: string }> = [];

  while ((match = questionRe.exec(content)) !== null) {
    const question = (match[1] || match[2] || "").trim();
    if (question) matches.push({ index: match.index, question });
  }

  if (matches.length === 0) return null;

  for (let i = 0; i < matches.length; i++) {
    const start = matches[i].index + matches[i].question.length + 10; // skip past the question line
    const end = i + 1 < matches.length ? matches[i + 1].index : content.length;
    // Grab the text between this question and the next, strip markdown syntax
    const rawAnswer = content
      .slice(start, end)
      .replace(/^#+\s.*/gm, "") // remove sub-headings
      .replace(/\*\*/g, "")
      .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1") // strip links
      .trim();
    const answer = rawAnswer.split(/\n\n/)[0].trim(); // first paragraph only
    if (answer) pairs.push({ question: matches[i].question, answer });
  }

  if (pairs.length === 0) return null;

  const schema = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    mainEntity: pairs.map(({ question, answer }) => ({
      "@type": "Question",
      name: question,
      acceptedAnswer: { "@type": "Answer", text: answer },
    })),
  };

  return JSON.stringify(schema);
}

// ---------------------------------------------------------------------------
// ItemList
// ---------------------------------------------------------------------------

/**
 * Build a JSON-LD ItemList schema for /tools and /resources pages.
 */
export function buildItemListSchema(
  items: Array<{ name: string; url: string; description: string }>,
  pageUrl: string
): string {
  const schema = {
    "@context": "https://schema.org",
    "@type": "ItemList",
    url: pageUrl,
    numberOfItems: items.length,
    itemListElement: items.map((item, index) => ({
      "@type": "ListItem",
      position: index + 1,
      name: item.name,
      url: item.url,
      description: item.description,
    })),
  };

  return JSON.stringify(schema);
}

// ---------------------------------------------------------------------------
// HowTo
// ---------------------------------------------------------------------------

const HOW_TO_TAGS = new Set(["tutorial", "walkthrough", "step-by-step", "how-to"]);

/**
 * Return true if any tag in the list matches HowTo trigger tags.
 */
export function isHowToPost(tags?: string[]): boolean {
  if (!tags || tags.length === 0) return false;
  return tags.some((t) => HOW_TO_TAGS.has(t.toLowerCase()));
}

/**
 * Extract step text from H2/H3 numbered headings in markdown content.
 * Patterns matched:
 *   ## 1. Step title
 *   ### Step 1: Step title
 *   ## Step 1 — Step title
 */
export function extractHowToSteps(content: string): string[] {
  const stepRe =
    /^#{2,3}\s+(?:step\s+)?(\d+)[.:)\s—–-]+(.+)/gim;
  const steps: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = stepRe.exec(content)) !== null) {
    const stepText = match[2].trim();
    if (stepText) steps.push(stepText);
  }
  return steps;
}

/**
 * Build a JSON-LD HowTo schema.
 * If steps array is empty, returns null (no point emitting an empty HowTo).
 */
export function buildHowToSchema(
  title: string,
  steps: string[],
  description?: string
): string | null {
  if (steps.length === 0) return null;

  const schema: Record<string, unknown> = {
    "@context": "https://schema.org",
    "@type": "HowTo",
    name: title,
    ...(description && { description }),
    step: steps.map((text, index) => ({
      "@type": "HowToStep",
      position: index + 1,
      name: text,
      text,
    })),
  };

  return JSON.stringify(schema);
}

// ---------------------------------------------------------------------------
// WebSite
// ---------------------------------------------------------------------------

/**
 * Build a JSON-LD WebSite schema for the site root.
 * Includes a SearchAction potentialAction pointing to /search.
 */
export function buildWebSiteSchema(config: {
  title: string;
  url: string;
  description: string;
}): string {
  const schema = {
    "@context": "https://schema.org",
    "@type": "WebSite",
    name: config.title,
    url: config.url,
    description: config.description,
    potentialAction: {
      "@type": "SearchAction",
      target: {
        "@type": "EntryPoint",
        urlTemplate: `${config.url}/search?q={search_term_string}`,
      },
      "query-input": "required name=search_term_string",
    },
  };
  return JSON.stringify(schema);
}

// ---------------------------------------------------------------------------
// BreadcrumbList
// ---------------------------------------------------------------------------

/**
 * Build a JSON-LD BreadcrumbList for a post/page.
 * Generates: Home > [Category >] Post Title
 */
export function buildBreadcrumbSchema(
  pageUrl: string,
  siteUrl: string,
  title: string,
  category?: string
): string {
  const items: Array<{ "@type": string; position: number; name: string; item: string }> = [
    { "@type": "ListItem", position: 1, name: "Home", item: siteUrl },
  ];

  if (category) {
    items.push({
      "@type": "ListItem",
      position: 2,
      name: category,
      item: `${siteUrl}/category/${encodeURIComponent(category)}`,
    });
    items.push({ "@type": "ListItem", position: 3, name: title, item: pageUrl });
  } else {
    items.push({ "@type": "ListItem", position: 2, name: title, item: pageUrl });
  }

  const schema = {
    "@context": "https://schema.org",
    "@type": "BreadcrumbList",
    itemListElement: items,
  };
  return JSON.stringify(schema);
}
