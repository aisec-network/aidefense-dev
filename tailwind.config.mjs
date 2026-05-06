import typography from "@tailwindcss/typography";

export default {
  content: ["./src/**/*.{astro,html,js,jsx,ts,tsx,md,mdx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        // These pull from CSS vars set per-cluster on <body>. Tailwind's
        // utility classes still produce expected output; the var resolves
        // at paint time.
        sans: ["var(--font-body)", "system-ui", "sans-serif"],
        body: ["var(--font-body)", "system-ui", "sans-serif"],
        display: ["var(--font-display)", "system-ui", "sans-serif"],
        mono: ["var(--font-mono)", "ui-monospace", "monospace"],
      },
      colors: {
        accent: {
          50:  "rgb(var(--accent-50)  / <alpha-value>)",
          100: "rgb(var(--accent-100) / <alpha-value>)",
          200: "rgb(var(--accent-200) / <alpha-value>)",
          300: "rgb(var(--accent-300) / <alpha-value>)",
          400: "rgb(var(--accent-400) / <alpha-value>)",
          500: "rgb(var(--accent-500) / <alpha-value>)",
          600: "rgb(var(--accent-600) / <alpha-value>)",
          700: "rgb(var(--accent-700) / <alpha-value>)",
          800: "rgb(var(--accent-800) / <alpha-value>)",
          900: "rgb(var(--accent-900) / <alpha-value>)",
          950: "rgb(var(--accent-950) / <alpha-value>)",
        },
      },
      typography: () => ({
        DEFAULT: {
          css: {
            maxWidth: "var(--body-max-ch, 72ch)",
            "code::before": { content: "" },
            "code::after": { content: "" },
            code: {
              fontWeight: "500",
              backgroundColor: "rgb(var(--muted) / 1)",
              padding: "0.15em 0.35em",
              borderRadius: "0.25rem",
            },
            "pre code": { backgroundColor: "transparent", padding: 0 },
            a: {
              color: "rgb(var(--accent-700))",
              textDecorationThickness: "1px",
              textUnderlineOffset: "0.2em",
              fontWeight: "500",
            },
            "a:hover": { color: "rgb(var(--accent-600))" },
            "h1, h2, h3, h4": { fontFamily: "var(--font-display)" },
          },
        },
      }),
    },
  },
  plugins: [typography],
};
