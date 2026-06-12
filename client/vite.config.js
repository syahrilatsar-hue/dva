import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd());

  return {
    root: path.resolve(__dirname),
    plugins: [react()],
    build: {
      outDir: path.resolve(__dirname, 'dist'),
      emptyOutDir: true,
      manifest: true,
    },
    define: {
      __APP_CONFIG__: {
        trackerIframeUrl: env.VITE_TRACKER_IFRAME_URL || '',
      },
    },
    server: {
      port: 5173,
      proxy: {
        '/api': env.VITE_APP_API_BASE || 'http://localhost:3000',
        '/oauth': env.VITE_APP_API_BASE || 'http://localhost:3000',
      },
    },
  };
});
