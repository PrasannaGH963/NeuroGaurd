/***** Tailwind CSS Config *****/
/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,jsx,ts,tsx}',
  ],
  theme: {
    extend: {
      colors: {
        terminal: {
          bg: '#0f172a',
          text: '#a7f3d0',
          accent: '#22c55e',
          danger: '#ef4444',
        }
      },
      boxShadow: {
        glow: '0 0 20px rgba(34, 197, 94, 0.25)'
      }
    },
    fontFamily: {
      mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'monospace']
    }
  },
  plugins: [],
}
