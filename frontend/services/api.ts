import axios from "axios";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

const api = axios.create({
  baseURL: API_URL,
  headers: {
    "Content-Type": "application/json",
  },
  // Send cookies (accessToken, refreshToken) on every request
  withCredentials: true,
});

// Request interceptor — attach JWT token from localStorage as Bearer header
api.interceptors.request.use(
  (config) => {
    if (typeof window !== "undefined") {
      const token = localStorage.getItem("accessToken");
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
    }
    return config;
  },
  (error) => Promise.reject(error),
);

// Track whether a refresh is in progress to avoid parallel refresh calls
let isRefreshing = false;
let pendingRequests: Array<(token: string) => void> = [];

const processQueue = (token: string) => {
  pendingRequests.forEach((cb) => cb(token));
  pendingRequests = [];
};

// Response interceptor — auto-refresh access token on 401, then retry
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Only attempt refresh once per request (prevent infinite loops)
    if (
      axios.isAxiosError(error) &&
      error.response?.status === 401 &&
      !originalRequest._retry &&
      // Don't retry refresh or login endpoints
      !originalRequest.url?.includes("/api/auth/refresh") &&
      !originalRequest.url?.includes("/api/auth/login")
    ) {
      if (isRefreshing) {
        // Queue this request until refresh completes
        return new Promise((resolve, reject) => {
          pendingRequests.push((token: string) => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            resolve(api(originalRequest));
          });
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Attempt token refresh using the httpOnly refreshToken cookie
        const refreshResponse = await api.post("/api/auth/refresh");
        // On success the backend sets a new accessToken cookie.
        // We also need to update localStorage if the refresh response contains the new token.
        // The backend's /refresh endpoint only sets a cookie — we need to re-fetch /me
        // to confirm the session is still valid. For now, just clear localStorage token
        // so the next request falls back to the cookie.
        if (typeof window !== "undefined") {
          // Remove stale token; the cookie will carry auth for the retried request
          localStorage.removeItem("accessToken");
        }

        // Re-attempt /me to get a fresh token value from the response (if available)
        // The interceptor will now use the cookie for the retry
        delete originalRequest.headers.Authorization;
        processQueue("");
        return api(originalRequest);
      } catch (refreshError) {
        // Refresh failed — clear session and redirect to login
        pendingRequests = [];
        if (typeof window !== "undefined") {
          localStorage.removeItem("accessToken");
          localStorage.removeItem("user");
          window.location.href = "/login";
        }
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  },
);

// Auth API
export const authApi = {
  register: (data: {
    username: string;
    email: string;
    password: string;
    confirmPassword: string;
  }) => api.post("/api/auth/register", data),
  login: (data: { email: string; password: string }) =>
    api.post("/api/auth/login", data),
  me: () => api.get("/api/auth/me"),
  logout: () => api.post("/api/auth/logout"),
  refresh: () => api.post("/api/auth/refresh"),
  updateProfile: (data: {
    username?: string;
    phoneNumber?: string;
    address?: string;
    bio?: string;
    photo?: string;
  }) => api.put("/api/auth/profile", data),
};

// Transaction API
export const transactionApi = {
  add: (data: {
    type: "INCOME" | "EXPENSE";
    amount: number;
    description?: string;
  }) => api.post("/api/transactions", data),
  getAll: () => api.get("/api/transactions"),
};

// Loan API
export const loanApi = {
  apply: (data: {
    loanAmount: number;
    monthlyIncome: number;
    monthlyExpense: number;
    purpose?: string;
  }) => api.post("/api/loans/apply", data),
  getMyLoans: () => api.get("/api/loans/my"),
};

// Admin API
export const adminApi = {
  getAllLoans: () => api.get("/api/admin/loans"),
  getPendingLoans: () => api.get("/api/admin/loans/pending"),
  getLoansFiltered: (params: {
    page?: number;
    size?: number;
    status?: string;
    riskLevel?: string;
    from?: string;
    to?: string;
  }) => api.get("/api/admin/loans/paged", { params }),
  decideLoan: (loanId: string, data: { decision: string; note?: string }) =>
    api.post(`/api/admin/loans/${loanId}/decide`, data),
  getAnalytics: () => api.get("/api/admin/analytics"),
  getUsers: () => api.get("/api/admin/users"),
  getUserProfile: (userId: number | string) =>
    api.get(`/api/admin/users/${userId}`),
  getAuditLogs: () => api.get("/api/admin/audit-logs"),
};

// Dashboard summary (user's own financial summary)
export const dashboardApi = {
  getSummary: () => api.get("/api/dashboard/summary"),
};

export default api;
