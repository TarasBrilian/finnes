import type { Config } from 'tailwindcss';

/**
 * Finnes — blue & white institutional palette.
 *
 * Strictly three families: light blue, dark blue (navy), and white. The Cirebon
 * Mega Mendung cloud motif lives in `public/mega-mendung.svg` (a real asset),
 * used deliberately as the navy hero banner — never as a full-page wallpaper.
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
        // Single blue scale: light (50) → navy (950).
        blue: {
          50: '#eff5ff',
          100: '#dce8ff',
          200: '#bcd3ff',
          300: '#8fb4ff',
          400: '#5b8cf0',
          500: '#2f63db',
          600: '#2249b5',
          700: '#1b3a8f',
          800: '#152c6b',
          900: '#0e1f49',
          950: '#081230',
        },
        // Alias kept so existing `brand-*` class usages keep working (= blue).
        brand: {
          50: '#eff5ff',
          100: '#dce8ff',
          500: '#2f63db',
          600: '#2249b5',
          700: '#1b3a8f',
        },
        ink: {
          DEFAULT: '#0e1f49', // navy text
          muted: '#465879',
          faint: '#8a99b8',
        },
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px rgba(14, 31, 73, 0.04), 0 10px 30px -20px rgba(14, 31, 73, 0.22)',
        lift: '0 2px 6px rgba(14, 31, 73, 0.06), 0 22px 48px -28px rgba(14, 31, 73, 0.32)',
      },
      backgroundImage: {
        'blue-spectrum': 'linear-gradient(120deg, #0e1f49 0%, #2249b5 50%, #5b8cf0 100%)',
      },
      keyframes: {
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'fade-up': 'fadeUp 0.5s ease-out both',
      },
    },
  },
  plugins: [],
};

export default config;
