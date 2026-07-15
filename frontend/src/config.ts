// Using Vite environment variables
// This defaults to localhost for development, but uses the VITE_API_URL when deployed to Netlify.

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

export const API_URL = `${API_BASE_URL}/api`;

export const getWsUrl = (path: string) => {
  if (API_BASE_URL) {
    const wsBase = API_BASE_URL.replace(/^http/, 'ws');
    return `${wsBase}/api${path}`;
  }
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}/api${path}`;
};
