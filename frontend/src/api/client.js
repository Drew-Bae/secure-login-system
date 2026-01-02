import axios from "axios";

// Default local backend
const baseURL = process.env.REACT_APP_API_URL || "http://localhost:5000";

const api = axios.create({
  baseURL,
  withCredentials: true, // REQUIRED for HttpOnly cookie auth
});

export default api;
