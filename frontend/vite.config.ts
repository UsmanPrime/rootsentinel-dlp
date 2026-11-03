import { defineConfig } from 'vite';

// The Phase 01 shell uses Vite's built-in TSX transform. No API is simulated.
// The caller can direct artifacts outside synchronized source storage.
export default defineConfig({
  build: { outDir: process.env.ROOTSENTINEL_FRONTEND_DIST || 'dist', emptyOutDir: false },
});
