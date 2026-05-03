export interface SisterSite {
  domain: string;
  url: string;
  title: string;
  tagline: string;
}

export interface SiteConfig {
  domain: string;
  url: string;
  title: string;
  tagline: string;
  description: string;
  byline: string;
  language: string;
  locale: string;
  themeColor: string;
  brand: { accentHue: number };
  social: { twitter?: string; rss: string };
  email: { contact: string; abuse: string; editor: string };
  newsletter: {
    enabled: boolean;
    provider?: "beehiiv" | "mailerlite" | "convertkit" | "buttondown" | "none";
    embedUrl?: string;
  };
  affiliate: { disclosure: string };
  sister: SisterSite[];
  analytics: { plausibleDomain?: string; ga4Id?: string; cfBeaconToken?: string };
}

export const portfolio: SisterSite[] = [
  { domain: "adversarialml.dev", url: "https://adversarialml.dev", title: "Adversarial ML", tagline: "Working adversarial ML — exploits, defenses, and the gap between" },
  { domain: "ai-alert.org", url: "https://ai-alert.org", title: "AI Alert", tagline: "AI incident & vulnerability tracker" },
  { domain: "aiattacks.dev", url: "https://aiattacks.dev", title: "AI Attacks", tagline: "Practitioner-grade AI red team techniques and tooling" },
  { domain: "aidefense.dev", url: "https://aidefense.dev", title: "AI Defense", tagline: "Defensive AI engineering — guardrails, hardening, response" },
  { domain: "aiincidents.org", url: "https://aiincidents.org", title: "AI Incidents", tagline: "AI incidents, model failures, and adversarial-use cases — dated and sourced" },
  { domain: "aimoderationtools.com", url: "https://aimoderationtools.com", title: "AI Moderation Tools", tagline: "Honest reviews and benchmarks of AI content-moderation tooling" },
  { domain: "aiprivacy.report", url: "https://aiprivacy.report", title: "AI Privacy Report", tagline: "AI privacy regulation, compliance, and enforcement, sourced" },
  { domain: "aisec.blog", url: "https://aisec.blog", title: "AI Sec", tagline: "Offensive AI security writeups" },
  { domain: "aisecbench.com", url: "https://aisecbench.com", title: "AI Sec Bench", tagline: "Benchmarks and evaluations of AI security tools" },
  { domain: "aisecdigest.com", url: "https://aisecdigest.com", title: "AI Sec Digest", tagline: "Curated AI security news, daily" },
  { domain: "aisecreviews.com", url: "https://aisecreviews.com", title: "AI Sec Reviews", tagline: "Reviews of AI security products and platforms" },
  { domain: "aisecweekly.com", url: "https://aisecweekly.com", title: "AI Sec Weekly", tagline: "Weekly digest of AI security news and analysis" },
  { domain: "bestaisecuritytools.com", url: "https://bestaisecuritytools.com", title: "Best AI Security Tools", tagline: "Comparing the AI security tooling landscape, with numbers" },
  { domain: "bestllmscanners.com", url: "https://bestllmscanners.com", title: "Best LLM Scanners", tagline: "Comparing LLM security scanners and detection tools" },
  { domain: "guardml.io", url: "https://guardml.io", title: "GuardML", tagline: "Defensive AI & guardrails" },
  { domain: "jailbreakdb.com", url: "https://jailbreakdb.com", title: "JailbreakDB", tagline: "An indexed catalog of working LLM jailbreak techniques" },
  { domain: "jailbreaks.fyi", url: "https://jailbreaks.fyi", title: "Jailbreaks FYI", tagline: "Working LLM jailbreak techniques, sourced and dated" },
  { domain: "llmops.report", url: "https://llmops.report", title: "LLMOps Report", tagline: "Operating LLMs in production — eval, observability, cost, latency" },
  { domain: "mlcves.com", url: "https://mlcves.com", title: "ML CVEs", tagline: "CVEs in ML libraries, frameworks, and the AI/ML supply chain" },
  { domain: "mlmonitoring.report", url: "https://mlmonitoring.report", title: "ML Monitoring Report", tagline: "Production ML monitoring, drift, and reliability" },
  { domain: "mlobserve.com", url: "https://mlobserve.com", title: "ML Observe", tagline: "ML observability deep dives — drift, debugging, monitoring" },
  { domain: "mlopsplatforms.com", url: "https://mlopsplatforms.com", title: "MLOps Platforms", tagline: "Honest reviews and comparisons of MLOps platforms" },
  { domain: "neuralwatch.org", url: "https://neuralwatch.org", title: "NeuralWatch", tagline: "AI policy & ethics watchdog" },
  { domain: "promptinjection.report", url: "https://promptinjection.report", title: "Prompt Injection Report", tagline: "Prompt injection PoCs, taxonomy, and primary sources" },
  { domain: "sentryml.com", url: "https://sentryml.com", title: "SentryML", tagline: "ML observability & MLOps" },
  { domain: "techsentinel.news", url: "https://techsentinel.news", title: "Tech Sentinel", tagline: "Cybersecurity news, daily" },
];

export const siteConfig: SiteConfig = {
  domain: "aidefense.dev",
  url: "https://aidefense.dev",
  title: "AI Defense",
  tagline: "Defensive AI engineering — guardrails, hardening, response.",
  description:
    "Engineering-focused coverage of defensive AI. Guardrail architecture, classifier ensembles, model hardening, output filtering, refusal training, and the response patterns that hold under adversarial pressure in production systems.",
  byline: "AI Defense Editorial",
  language: "en",
  locale: "en_US",
  themeColor: "#0a0a0a",
  brand: { accentHue: 220 },
  social: { rss: "/rss.xml" },
  email: {
    contact: "hello@aidefense.dev",
    abuse: "abuse@aidefense.dev",
    editor: "editor@aidefense.dev",
  },
  newsletter: { enabled: true, provider: "none" },
  affiliate: {
    disclosure:
      "Some links in this post are affiliate links. We may earn a small commission at no extra cost to you. Editorial coverage is not influenced by affiliate relationships.",
  },
  sister: portfolio.filter((s) => s.domain !== "aidefense.dev"),
  analytics: {},
};
