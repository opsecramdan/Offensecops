/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // OffenSecOps dark cyber theme
        bg: {
          primary: '#0a0c10',
          secondary: '#0d1117',
          tertiary: '#161b22',
          card: '#1a2130',
          hover: '#1f2937',
        },
        accent: {
          primary: '#00d4aa',    // cyber teal
          secondary: '#ff4757',  // alert red
          warning: '#ffa502',    // warning amber
          info: '#3b82f6',       // info blue
          purple: '#8b5cf6',     // purple accent
        },
        border: {
          default: '#21262d',
          active: '#00d4aa',
          muted: '#30363d',
        },
        text: {
          primary: '#e6edf3',
          secondary: '#8b949e',
          muted: '#484f58',
          accent: '#00d4aa',
        },
        severity: {
          critical: '#ff4757',
          high: '#ff6b35',
          medium: '#ffa502',
          low: '#3b82f6',
          info: '#8b5cf6',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Syne', 'system-ui', 'sans-serif'],
        display: ['Syne', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow': 'glow 2s ease-in-out infinite alternate',
        'scan-line': 'scanLine 3s linear infinite',
        'fade-in': 'fadeIn 0.3s ease-in',
        'slide-in': 'slideIn 0.3s ease-out',
      },
      keyframes: {
        glow: {
          '0%': { boxShadow: '0 0 5px #00d4aa33' },
          '100%': { boxShadow: '0 0 20px #00d4aa66, 0 0 40px #00d4aa22' },
        },
        scanLine: {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideIn: {
          '0%': { transform: 'translateX(-10px)', opacity: '0' },
          '100%': { transform: 'translateX(0)', opacity: '1' },
        },
      },
      backgroundImage: {
        'grid-pattern': "linear-gradient(rgba(0, 212, 170, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 212, 170, 0.03) 1px, transparent 1px)",
        'cyber-gradient': 'linear-gradient(135deg, #0a0c10 0%, #0d1117 50%, #0a0e1a 100%)',
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
    },
  },
  plugins: [],
}
