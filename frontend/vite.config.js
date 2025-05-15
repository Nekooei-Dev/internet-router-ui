import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      external: ['fs', 'path', 'net', 'tls', 'crypto'], // جلوگیری از خطاهای external
    },
  },
  server: {
    port: 3000,
  },
});
