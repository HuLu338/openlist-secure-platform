import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Keep backend API traffic under a dedicated prefix so React routes like
      // /scans, /alerts, and /rules are never proxied away from the frontend.
      '/backend-api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/backend-api/, ''),
      },
    },
  },
})
