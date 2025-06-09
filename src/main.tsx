import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import './index.css';
import App from './App.tsx';

// Load OpenAI API key from environment variable into localStorage if not already set
const apiKeyFromEnv = import.meta.env.OPENAI_API_KEY;
if (apiKeyFromEnv && !localStorage.getItem('openai_api_key')) {
  localStorage.setItem('openai_api_key', apiKeyFromEnv);
  console.log('OpenAI API key loaded from environment variable into localStorage.');
}

createRoot(document.getElementById('root')!).render(
  // <StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  // </StrictMode>,
);
