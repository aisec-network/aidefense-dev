export interface IdentityFont {
  id: string;
  display: string;
  body: string;
  mono: string;
  google_fonts_url: string;
  stack_display: string;
  stack_body: string;
  stack_mono: string;
}

export interface IdentityPalette {
  id: string;
  hue: number;
  neutral_family: string;
  accent: string;
  accent_dark: string;
  surface: string;
  surface_alt: string;
  fg: string;
  fg_muted: string;
  border: string;
  surface_dark: string;
  surface_alt_dark: string;
  fg_dark: string;
  fg_muted_dark: string;
  border_dark: string;
}

export interface IdentityLayout {
  id: "magazine" | "dashboard" | "feed" | "directory" | "longform" | "kiosk";
  component: string;
  component_path: string;
  density: "loose" | "normal" | "dense";
  brief: string;
}

export interface IdentityVoice {
  id: string;
  label_latest: string;
  label_recent: string;
  label_featured: string;
  label_more: string;
  nav_posts: string;
  nav_about: string;
  cta_subscribe: string;
  cta_subscribe_desc: string;
  cta_button: string;
  site_motto: string;
}

export interface Identity {
  font: IdentityFont;
  palette: IdentityPalette;
  layout: IdentityLayout;
  voice: IdentityVoice;
}

export const identity: Identity = {
  "font": {
    "id": "f26_mono_jetbrains_inter",
    "display": "JetBrains Mono",
    "body": "Inter",
    "mono": "JetBrains Mono",
    "google_fonts_url": "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap",
    "stack_display": "\"JetBrains Mono\", ui-monospace, SFMono-Regular, Menlo, monospace",
    "stack_body": "Inter, \"Helvetica Neue\", system-ui, sans-serif",
    "stack_mono": "\"JetBrains Mono\", ui-monospace, monospace"
  },
  "palette": {
    "id": "p15_h338_slate",
    "hue": 338,
    "neutral_family": "slate",
    "accent": "223 22 96",
    "accent_dark": "242 95 149",
    "surface": "255 255 255",
    "surface_alt": "248 250 252",
    "fg": "15 23 42",
    "fg_muted": "71 85 105",
    "border": "226 232 240",
    "surface_dark": "15 23 42",
    "surface_alt_dark": "30 41 59",
    "fg_dark": "248 250 252",
    "fg_muted_dark": "148 163 184",
    "border_dark": "51 65 85"
  },
  "layout": {
    "id": "longform",
    "component": "HomeCivic",
    "component_path": "@components/clusters/HomeCivic.astro",
    "density": "loose",
    "brief": "Narrow centered column, big serif type, generous whitespace."
  },
  "voice": {
    "id": "v03_research",
    "label_latest": "Recent research",
    "label_recent": "Archive",
    "label_featured": "Working paper",
    "label_more": "Read the paper",
    "nav_posts": "Papers",
    "nav_about": "About",
    "cta_subscribe": "Research digest",
    "cta_subscribe_desc": "New papers, summaries, and citations.",
    "cta_button": "Subscribe",
    "site_motto": "Sourced research and analysis."
  }
} as const;
