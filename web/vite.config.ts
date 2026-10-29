import react from '@vitejs/plugin-react';
import process from 'node:process';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        // The app shipped as one ~2.3 MB chunk, so every visitor downloaded the
        // charting and table libraries before the login form could render.
        // Splitting the three heavy vendors lets them cache independently.
        manualChunks: {
          echarts: ['echarts'],
          graph: ['@antv/g6'],
          antd: ['antd', '@ant-design/pro-components'],
          react: ['react', 'react-dom', 'react-router-dom']
        }
      }
    }
  },
  server: {
    port: 5173,
    proxy: {
      '/api': process.env.VITE_API_PROXY_TARGET ?? 'http://localhost:8081'
    }
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test/setup.ts',
    globals: true
  }
});
