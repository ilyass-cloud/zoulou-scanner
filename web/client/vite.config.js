import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// The React SPA is a pure frontend: every data call goes to the existing Flask
// backend under /api. In dev we proxy /api (and its SSE log stream) to Flask so
// the browser only ever talks to the Vite origin. Override the backend with
// VITE_API_TARGET when Flask runs elsewhere.
const API_TARGET = process.env.VITE_API_TARGET || 'http://127.0.0.1:5000';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: API_TARGET,
        changeOrigin: true,
        // Server-Sent Events (live scan logs) must not be buffered.
        configure: (proxy) => {
          proxy.on('proxyReq', (proxyReq) => proxyReq.setHeader('Accept-Encoding', 'identity'));
        },
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
