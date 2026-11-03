import { defineConfig } from 'vite';

// The Phase 01 shell uses Vite's built-in TSX transform. No API is simulated.
// The caller can direct artifacts outside synchronized source storage.
export default defineConfig({
  server: { proxy: { '/api': { target: `http://127.0.0.1:${process.env.ROOTSENTINEL_API_PORT || '8000'}`, changeOrigin: false } } },
  build: { outDir: process.env.ROOTSENTINEL_FRONTEND_DIST || 'dist', emptyOutDir: false },
});
