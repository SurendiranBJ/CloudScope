/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        enterprise: {
          bg: '#0B1220',
          card: '#111827',
          accent: '#3B82F6',
          success: '#10B981',
          warning: '#F59E0B',
          critical: '#EF4444',
          border: '#1F2937',
          subtext: '#9CA3AF',
        }
      },
      fontFamily: {
        sans: ['Inter', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
