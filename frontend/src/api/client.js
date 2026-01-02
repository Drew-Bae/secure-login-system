import axios from "axios";

// Backend root (no /api here)
const base = process.env.REACT_APP_API_URL || "http://localhost:5000";

// IMPORTANT: append /api because backend routes are mounted at /api/...
const client = axios.create({
  baseURL: `${base}/api`,
  withCredentials: true,
});

export default client;
