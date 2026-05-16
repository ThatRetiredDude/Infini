import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const apiProxy = {
  target: 'http://localhost:3000',
  changeOrigin: true,
};

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': apiProxy,
      '/uploads': apiProxy,

      // Root-level scanner paths must hit Express in dev too. Without these,
      // Vite serves the SPA fallback and the monitoring layer never records the hit.
      '/.env': apiProxy,
      '/.git': apiProxy,
      '/.aws': apiProxy,
      '/.docker': apiProxy,
      '/.well-known/security.txt': apiProxy,
      '/wp-admin': apiProxy,
      '/wp-login.php': apiProxy,
      '/xmlrpc.php': apiProxy,
      '/phpmyadmin': apiProxy,
      '/phpMyAdmin': apiProxy,
      '/adminer.php': apiProxy,
      '/adminer': apiProxy,
      '/openapi.json': apiProxy,
      '/swagger.json': apiProxy,
      '/backup.sql': apiProxy,
      '/dump.sql': apiProxy,
      '/db_backup.zip': apiProxy,
      '/backups': apiProxy,
      '/robots.txt': apiProxy,
      '/login': apiProxy,
      '/grafana': apiProxy,
      '/user/password/send-reset-email': apiProxy,
      '/jenkins': apiProxy,
      '/users/sign_in': apiProxy,
      '/gitlab': apiProxy,
      '/actuator': apiProxy,
      '/owa': apiProxy,
      '/solr': apiProxy,
      '/console': apiProxy,
      '/signin': apiProxy,
      '/ecp': apiProxy,
      '/exports': apiProxy,
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 900,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return undefined;
          if (id.includes('@tiptap') || id.includes('prosemirror')) return 'vendor-tiptap';
          if (id.includes('dompurify')) return 'vendor-dompurify';
          return undefined;
        },
      },
    },
  },
});
