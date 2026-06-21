import type { Config } from 'tailwindcss';

/**
 * Finnes, blue & white institutional palette.
 *
 * Strictly three families: light blue, dark blue (navy), and white. The Cirebon
 * Mega Mendung cloud motif lives in `public/mega-mendung.svg` (a real asset),
 * used deliberately as the navy hero banner, never as a full-page wallpaper.
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
        // Dark "vault" surfaces for the immersive landing.
        midnight: {
          DEFAULT: '#060c1f', // near-black navy page floor
          900: '#081230',
          800: '#0b1838',
          700: '#102047',
          glow: '#1b3a8f',
        },
        // Bright accent that glows against midnight (batik highlight).
        accent: {
          DEFAULT: '#6ea8ff',
          soft: '#9cc4ff',
        },
      },
      fontFamily: {
        sans: ['"Plus Jakarta Sans"', 'ui-sans-serif', 'system-ui', 'Segoe UI', 'sans-serif'],
        display: ['"Bricolage Grotesque"', '"Plus Jakarta Sans"', 'ui-sans-serif', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        card: '0 1px 2px rgba(14, 31, 73, 0.04), 0 10px 30px -20px rgba(14, 31, 73, 0.22)',
        lift: '0 2px 6px rgba(14, 31, 73, 0.06), 0 22px 48px -28px rgba(14, 31, 73, 0.32)',
        glow: '0 0 0 1px rgba(110,168,255,0.15), 0 30px 80px -40px rgba(27,58,143,0.8)',
      },
      backgroundImage: {
        'blue-spectrum': 'linear-gradient(120deg, #0e1f49 0%, #2249b5 50%, #5b8cf0 100%)',
        'navy-panel': 'linear-gradient(135deg, #0c1c44 0%, #112556 55%, #1a3370 100%)',
        // Radial aurora used behind the dark hero.
        'aurora': 'radial-gradient(60% 50% at 50% 0%, rgba(47,99,219,0.30) 0%, rgba(27,58,143,0.10) 45%, rgba(6,12,31,0) 75%)',
      },
      keyframes: {
        fadeUp: {
          '0%': { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        marquee: {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(-50%)' },
        },
        drift: {
          '0%,100%': { transform: 'translate3d(0,0,0)' },
          '50%': { transform: 'translate3d(0,-14px,0)' },
        },
        glowpulse: {
          '0%,100%': { opacity: '0.55' },
          '50%': { opacity: '0.9' },
        },
      },
      animation: {
        'fade-up': 'fadeUp 0.5s ease-out both',
        marquee: 'marquee 34s linear infinite',
        drift: 'drift 12s ease-in-out infinite',
        glowpulse: 'glowpulse 7s ease-in-out infinite',
      },
    },
  },
  plugins: [],
};

export default config;
