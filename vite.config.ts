import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  server: {
    port: 3000,
    host: '0.0.0.0',
  },
  define: {
    // Provide server GEMINI_API_KEY to client if defined in container env
    '__APP_GEMINI_API_KEY__': JSON.stringify(process.env.GEMINI_API_KEY || ''),
  },
});
