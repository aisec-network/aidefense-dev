/**
 * Cluster aesthetic system. Each of the portfolio's domains belongs to one of
 * five visual families. Within a family, sites share typography + layout DNA;
 * across families, the visual languages are sharply different so the network
 * feels intentional rather than templated.
 *
 * Per-site accent color is still controlled by `siteConfig.brand.accentHue`
 * and tinted into a 50..950 ramp at runtime via globals.css. The cluster
 * controls everything else: fonts, neutrals, layout shape, hero treatment.
 */

export type ClusterId =
  | "offensive"
  | "engineering"
  | "news"
  | "policy"
  | "defensive";

export interface ClusterDefinition {
  id: ClusterId;
  label: string;
  /** One-line aesthetic brief. Renders nowhere — kept for reference. */
  brief: string;
  fonts: {
    /** Google Fonts family name for headings. */
    display: string;
    /** Google Fonts family name for body. */
    body: string;
    /** Mono font (always JetBrains Mono — kept here so cluster owns it). */
    mono: string;
    /** Weights to load. */
    weights: { display: number[]; body: number[] };
    /** CSS font-family stacks with system fallbacks. */
    stacks: { display: string; body: string; mono: string };
  };
  /**
   * Neutral palette used for backgrounds, ink, and surfaces. Light + dark
   * variants. RGB triplets so CSS-vars work with `rgb(var(--bg) / <alpha>)`.
   */
  neutrals: {
    light: NeutralPalette;
    dark: NeutralPalette;
  };
  /** Homepage layout variant — see components/cluster/Home*.astro */
  homepageLayout:
    | "editorial"
    | "dashboard"
    | "newspaper"
    | "civic"
    | "product";
  /** Whether posts get drop caps. */
  postDropCaps: boolean;
  /** Hero ratio for post pages. */
  heroAspect: "16:9" | "21:9" | "4:3";
  /** Body max-width override (ch). */
  bodyMaxCh: number;
}

interface NeutralPalette {
  bg: string;
  fg: string;
  muted: string;
  mutedFg: string;
  border: string;
  surface: string;
}

export const clusters: Record<ClusterId, ClusterDefinition> = {
  offensive: {
    id: "offensive",
    label: "Offensive Sec",
    brief:
      "Dark, technical, editorial. Mono headers + serif body. Greens/teals. Code-forward.",
    fonts: {
      display: "JetBrains Mono",
      body: "Lora",
      mono: "JetBrains Mono",
      weights: { display: [500, 700], body: [400, 500, 700] },
      stacks: {
        display:
          '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
        body: 'Lora, "Iowan Old Style", "Apple Garamond", Georgia, serif',
        mono: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      },
    },
    neutrals: {
      light: {
        bg: "250 250 249",
        fg: "20 24 24",
        muted: "243 244 240",
        mutedFg: "82 90 90",
        border: "225 228 222",
        surface: "255 255 255",
      },
      dark: {
        bg: "10 14 14",
        fg: "236 240 234",
        muted: "20 26 26",
        mutedFg: "152 162 158",
        border: "36 44 44",
        surface: "16 22 22",
      },
    },
    homepageLayout: "editorial",
    postDropCaps: false,
    heroAspect: "21:9",
    bodyMaxCh: 70,
  },

  engineering: {
    id: "engineering",
    label: "Engineering / MLOps",
    brief:
      "Clean, schematic, dashboardy. Sans-serif throughout. Blues. Diagram-friendly.",
    fonts: {
      display: "Inter",
      body: "Inter",
      mono: "JetBrains Mono",
      weights: { display: [600, 700, 800], body: [400, 500, 600] },
      stacks: {
        display: 'Inter, "Helvetica Neue", system-ui, sans-serif',
        body: 'Inter, "Helvetica Neue", system-ui, sans-serif',
        mono: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      },
    },
    neutrals: {
      light: {
        bg: "248 250 252",
        fg: "15 23 42",
        muted: "241 245 249",
        mutedFg: "71 85 105",
        border: "226 232 240",
        surface: "255 255 255",
      },
      dark: {
        bg: "8 12 22",
        fg: "226 232 240",
        muted: "17 24 39",
        mutedFg: "148 163 184",
        border: "30 41 59",
        surface: "13 20 35",
      },
    },
    homepageLayout: "dashboard",
    postDropCaps: false,
    heroAspect: "16:9",
    bodyMaxCh: 75,
  },

  news: {
    id: "news",
    label: "News / Tracker",
    brief:
      "Editorial newspaper. Serif headers, condensed sans for body. Reds + blacks. Dense.",
    fonts: {
      display: "Playfair Display",
      body: "Source Sans 3",
      mono: "JetBrains Mono",
      weights: { display: [700, 900], body: [400, 600, 700] },
      stacks: {
        display:
          '"Playfair Display", "Times New Roman", "Iowan Old Style", Georgia, serif',
        body: '"Source Sans 3", "Helvetica Neue", system-ui, sans-serif',
        mono: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      },
    },
    neutrals: {
      light: {
        bg: "253 252 250",
        fg: "12 12 12",
        muted: "245 244 240",
        mutedFg: "82 82 82",
        border: "224 224 220",
        surface: "255 255 255",
      },
      dark: {
        bg: "12 10 10",
        fg: "240 238 234",
        muted: "22 20 20",
        mutedFg: "168 162 158",
        border: "44 40 40",
        surface: "18 16 16",
      },
    },
    homepageLayout: "newspaper",
    postDropCaps: true,
    heroAspect: "16:9",
    bodyMaxCh: 68,
  },

  policy: {
    id: "policy",
    label: "Policy / Watchdog",
    brief:
      "Civic, weighty, authoritative. Mixed serif. Earth tones + warning amber. Generous whitespace.",
    fonts: {
      display: "Source Serif 4",
      body: "Source Sans 3",
      mono: "JetBrains Mono",
      weights: { display: [600, 700], body: [400, 600] },
      stacks: {
        display:
          '"Source Serif 4", "Iowan Old Style", "Apple Garamond", Georgia, serif',
        body: '"Source Sans 3", "Helvetica Neue", system-ui, sans-serif',
        mono: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      },
    },
    neutrals: {
      light: {
        bg: "251 248 240",
        fg: "30 26 18",
        muted: "245 240 228",
        mutedFg: "94 84 64",
        border: "228 220 200",
        surface: "255 252 244",
      },
      dark: {
        bg: "20 17 12",
        fg: "236 230 218",
        muted: "30 26 20",
        mutedFg: "168 158 138",
        border: "52 46 36",
        surface: "26 22 16",
      },
    },
    homepageLayout: "civic",
    postDropCaps: true,
    heroAspect: "16:9",
    bodyMaxCh: 72,
  },

  defensive: {
    id: "defensive",
    label: "Defensive / Tools",
    brief:
      "Product-page polish. Bold sans. Purples/violets. Comparison tables, callouts.",
    fonts: {
      display: "Manrope",
      body: "Inter",
      mono: "JetBrains Mono",
      weights: { display: [700, 800], body: [400, 500, 600] },
      stacks: {
        display:
          'Manrope, Inter, "Helvetica Neue", system-ui, sans-serif',
        body: 'Inter, "Helvetica Neue", system-ui, sans-serif',
        mono: '"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      },
    },
    neutrals: {
      light: {
        bg: "252 251 254",
        fg: "20 16 32",
        muted: "244 241 250",
        mutedFg: "84 78 110",
        border: "228 222 240",
        surface: "255 255 255",
      },
      dark: {
        bg: "14 10 24",
        fg: "236 232 248",
        muted: "22 18 36",
        mutedFg: "162 156 188",
        border: "44 36 66",
        surface: "20 16 32",
      },
    },
    homepageLayout: "product",
    postDropCaps: false,
    heroAspect: "16:9",
    bodyMaxCh: 72,
  },
};

/**
 * Domain → cluster map. Adding a new site? Add it here.
 * Used by the Footer cluster grouping and by build-time consistency checks.
 */
export const domainCluster: Record<string, ClusterId> = {
  // Offensive
  "aisec.blog": "offensive",
  "jailbreaks.fyi": "offensive",
  "jailbreakdb.com": "offensive",
  "aiattacks.dev": "offensive",
  "promptinjection.report": "offensive",
  "adversarialml.dev": "offensive",
  "mlcves.com": "offensive",

  // Engineering / MLOps
  "sentryml.com": "engineering",
  "llmops.report": "engineering",
  "mlobserve.com": "engineering",
  "mlmonitoring.report": "engineering",
  "mlopsplatforms.com": "engineering",

  // News / Tracker
  "ai-alert.org": "news",
  "aiincidents.org": "news",
  "techsentinel.news": "news",
  "aisecdigest.com": "news",
  "aisecweekly.com": "news",

  // Policy / Watchdog
  "neuralwatch.org": "policy",
  "aiprivacy.report": "policy",

  // Defensive / Tools
  "guardml.io": "defensive",
  "aidefense.dev": "defensive",
  "aimoderationtools.com": "defensive",
  "aisecreviews.com": "defensive",
  "bestaisecuritytools.com": "defensive",
  "bestllmscanners.com": "defensive",
  "aisecbench.com": "defensive",
};

export function getCluster(domain: string): ClusterDefinition {
  const id = domainCluster[domain] ?? "offensive";
  return clusters[id];
}

/**
 * Compute an 11-stop accent ramp (50..950) as "R G B" triplets from a hue.
 *
 * Designed to track Tailwind's color ramp shape so any hue produces a usable
 * ramp without per-site tuning. Saturation is high in the 400..700 range and
 * tapers at the extremes; lightness follows a near-Tailwind curve.
 */
export function hueToAccentRamp(hue: number): Record<number, string> {
  // Lightness (0..1) and saturation (0..1) per stop. Mirrors Tailwind's shape.
  const stops: Array<[number, number, number]> = [
    [50, 0.97, 0.55],
    [100, 0.93, 0.65],
    [200, 0.85, 0.75],
    [300, 0.74, 0.82],
    [400, 0.62, 0.86],
    [500, 0.52, 0.84],
    [600, 0.45, 0.80],
    [700, 0.38, 0.76],
    [800, 0.31, 0.70],
    [900, 0.24, 0.62],
    [950, 0.16, 0.55],
  ];
  const out: Record<number, string> = {};
  for (const [stop, l, s] of stops) {
    const [r, g, b] = hslToRgb(hue, s, l);
    out[stop] = `${r} ${g} ${b}`;
  }
  return out;
}

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  h = ((h % 360) + 360) % 360;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = l - c / 2;
  let r = 0, g = 0, b = 0;
  if (h < 60) [r, g, b] = [c, x, 0];
  else if (h < 120) [r, g, b] = [x, c, 0];
  else if (h < 180) [r, g, b] = [0, c, x];
  else if (h < 240) [r, g, b] = [0, x, c];
  else if (h < 300) [r, g, b] = [x, 0, c];
  else [r, g, b] = [c, 0, x];
  return [
    Math.round((r + m) * 255),
    Math.round((g + m) * 255),
    Math.round((b + m) * 255),
  ];
}

/**
 * Build a Google Fonts CSS URL that loads only the weights this cluster needs.
 * Falls back gracefully if the network is offline (system stacks kick in).
 */
export function googleFontsHref(cluster: ClusterDefinition): string {
  const families: string[] = [];
  const fam = (name: string, weights: number[]) =>
    `${name.replace(/ /g, "+")}:wght@${weights.join(";")}`;
  families.push(fam(cluster.fonts.display, cluster.fonts.weights.display));
  if (cluster.fonts.body !== cluster.fonts.display) {
    families.push(fam(cluster.fonts.body, cluster.fonts.weights.body));
  }
  // Mono (small set, only what we use for code)
  families.push("JetBrains+Mono:wght@400;500;700");
  return `https://fonts.googleapis.com/css2?${families
    .map((f) => `family=${f}`)
    .join("&")}&display=swap`;
}
