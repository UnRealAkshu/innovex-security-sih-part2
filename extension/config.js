// Local default: run `npm install && npm run dev` inside /server.
// For deployment, replace this with the public URL of the deployed scan API.
export const API_BASE_URL = "http://localhost:3000";

// Optional demo/access-control key. It is intentionally not treated as a secret.
export const EXTENSION_API_KEY = "";

export const API_ENDPOINTS = {
  scanUrl: `${API_BASE_URL}/api/scan/url`
};
