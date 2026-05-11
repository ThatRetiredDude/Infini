/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#07090c',
          900: '#0b0e13',
          800: '#11151c',
          700: '#1a2029',
          600: '#252d39',
          500: '#3a4554',
          400: '#5a6776',
          300: '#8b96a4',
          200: '#c2c9d2',
          100: '#e6eaef',
        },
        accent: {
          DEFAULT: '#34d399',
          dim: '#10b981',
          glow: '#6ee7b7',
        },
        danger: {
          DEFAULT: '#f43f5e',
          dim: '#be123c',
        },
        warning: {
          DEFAULT: '#f59e0b',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
    },
  },
  plugins: [],
};
