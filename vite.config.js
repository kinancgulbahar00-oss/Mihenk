import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Gelistirmede API istekleri ayni kokenden vekillenir; boylece oturum cerezi (SameSite=Strict)
// calisir ve arka uca CORS izni vermek gerekmez.
const API_TARGET = process.env.MIHENK_API_TARGET || 'http://127.0.0.1:8000';
const API_PATHS = ['/analyze', '/ioc', '/campaign', '/lists', '/brands', '/admin', '/health'];

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // Gelistirme sunucusu yalnizca bu makinede dinler; uretimde kullanilmaz
    host: '127.0.0.1',
    proxy: Object.fromEntries(API_PATHS.map((p) => [p, { target: API_TARGET, changeOrigin: false }])),
  },
  build: {
    sourcemap: false,
  },
});
