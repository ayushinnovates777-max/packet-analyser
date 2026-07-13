/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        dark: {
          900: '#020617', // Background
          800: '#0F172A', // Primary
          700: '#1E293B', // Secondary
        },
        primary: {
          500: '#0F172A',
          400: '#1E293B',
        },
        accent: '#22C55E', // CTA
        text: '#F8FAFC',
      },
      fontFamily: {
        sans: ['"Fira Sans"', 'sans-serif'],
        mono: ['"Fira Code"', 'monospace'],
      }
    },
  },
  plugins: [],
}
