import { defineConfig } from 'vite';

// Vite's built-in TSX transform; no plugin injects inline scripts, so the built app runs under the enforced CSP.
// The dev server proxies the API and /health to the local backend; no API is simulated.
// ROOTSENTINEL_FRONTEND_DIST can direct build output outside synchronized source storage.
export default defineConfig({
  server: { proxy: Object.fromEntries(['/api', '/health'].map((path) => [path, { target: `http://127.0.0.1:${process.env.ROOTSENTINEL_API_PORT || '8000'}`, changeOrigin: false }])) },
  build: { outDir: process.env.ROOTSENTINEL_FRONTEND_DIST || 'dist', emptyOutDir: false },
});
