import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react-swc";
import tailwindcss from "@tailwindcss/vite";

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), ''); // Load all env vars from .env
  
  // Get backend URL from environment or use localhost as fallback
  const backendUrl = env.VITE_API_BASE_URL || 'http://localhost:5000';
  
  return {
    plugins: [react(), tailwindcss()],
    define: {
      // Expose OPENAI_API_KEY to the frontend
      'import.meta.env.OPENAI_API_KEY': JSON.stringify(env.OPENAI_API_KEY),
      // Expose API base URL to the frontend
      'import.meta.env.VITE_API_BASE_URL': JSON.stringify(backendUrl)
    },
    server: {
      host: true,
      proxy: {
        // Dynamic proxy target based on environment variable
        '/api': {
          target: backendUrl, // Use environment variable for backend address
          changeOrigin: true,
          // secure: false, // Uncomment if your backend is http and Vite is https, though typically not needed for localhost
          // rewrite: (path) => path.replace(/^\/api/, ''), // Uncomment if your Flask routes don't include /api
        },
      },
    },
  };
});
