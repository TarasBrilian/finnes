import type { Config } from 'tailwindcss';

/**
 * Institutional / professional palette — restrained, not flashy.
 * `ink` for text, `slate` surfaces, a single calm `brand` blue for primary
 * actions, and semantic colors reserved for compliance status + trust-boundary
 * warnings.
 */
const config: Config = {
  content: [
    './app/**/*.{ts,tsx}',
    './components/**/*.{ts,tsx}',
    './lib/**/*.{ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef4ff',
          100: '#d9e6ff',
          500: '#2f5bd6',
          600: '#2748b0',
          700: '#1f3a8c',
        },
        ink: {
          DEFAULT: '#0f172a',
          muted: '#475569',
          faint: '#94a3b8',
        },
      },
      fontFamily: {
        sans: ['ui-sans-serif', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
};

export default config;
