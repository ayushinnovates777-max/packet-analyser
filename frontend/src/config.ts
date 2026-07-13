// Using Vite environment variables
// This defaults to localhost for development, but uses the VITE_API_URL when deployed to Netlify.

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001';

export const API_URL = `${API_BASE_URL}/api`;

// Helper to get WebSocket URL
export const getWsUrl = (path: string) => {
  const wsBase = API_BASE_URL.replace(/^http/, 'ws');
  return `${wsBase}/api${path}`;
};
