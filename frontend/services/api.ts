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

// Response interceptor — handle 401 auto logout
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (axios.isAxiosError(error) && error.response?.status === 401) {
      if (typeof window !== "undefined") {
        localStorage.removeItem("accessToken");
        localStorage.removeItem("user");
        window.location.href = "/login";
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
  decideLoan: (loanId: string, data: { decision: string; note?: string }) =>
    api.post(`/api/admin/loans/${loanId}/decide`, data),
};

export default api;
