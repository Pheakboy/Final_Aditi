import axios from "axios";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8080";

const api = axios.create({
  baseURL: API_URL,
  headers: { "Content-Type": "application/json" },
  withCredentials: true,
});

// Request interceptor — attach JWT from localStorage
api.interceptors.request.use(
  (config) => {
    if (typeof window !== "undefined") {
      const token = localStorage.getItem("accessToken");
      if (token) config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error),
);

let isRefreshing = false;
let pendingRequests: Array<(token: string) => void> = [];

const processQueue = (token: string) => {
  pendingRequests.forEach((cb) => cb(token));
  pendingRequests = [];
};

// Response interceptor — auto-refresh on 401
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (
      axios.isAxiosError(error) &&
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !originalRequest.url?.includes("/api/auth/refresh") &&
      !originalRequest.url?.includes("/api/auth/login")
    ) {
      if (isRefreshing) {
        return new Promise((resolve) => {
          pendingRequests.push((token: string) => {
            originalRequest.headers.Authorization = `Bearer ${token}`;
            resolve(api(originalRequest));
          });
        });
      }
      originalRequest._retry = true;
      isRefreshing = true;
      try {
        const res = await api.post("/api/auth/refresh");
        const newToken: string = res.data?.data?.accessToken;
        if (newToken && typeof window !== "undefined") {
          localStorage.setItem("accessToken", newToken);
        }
        if (originalRequest.headers) {
          originalRequest.headers.Authorization = `Bearer ${newToken ?? ""}`;
        }
        processQueue(newToken ?? "");
        return api(originalRequest);
      } catch {
        pendingRequests = [];
        if (typeof window !== "undefined") {
          localStorage.removeItem("accessToken");
          localStorage.removeItem("user");
          window.location.href = "/login";
        }
        return Promise.reject(error);
      } finally {
        isRefreshing = false;
      }
    }
    return Promise.reject(error);
  },
);

// ─── Auth API ────────────────────────────────────────────────────────────────
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

// ─── Transaction API ─────────────────────────────────────────────────────────
export const transactionApi = {
  add: (data: {
    type: "INCOME" | "EXPENSE";
    amount: number;
    description?: string;
  }) => api.post("/api/transactions", data),
  getAll: (params?: { type?: string; from?: string; to?: string }) =>
    api.get("/api/transactions", { params }),
  exportCSV: () =>
    api.get("/api/users/me/transactions/export", { responseType: "blob" }),
  importFile: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return api.post<{
      data: { imported: number; skipped: number; errors: string[] };
    }>("/api/transactions/import", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
  },
};

// ─── Loan API ────────────────────────────────────────────────────────────────
export const loanApi = {
  apply: (data: {
    loanAmount: number;
    monthlyIncome: number;
    monthlyExpense: number;
    purpose?: string;
  }) => api.post("/api/loans/apply", data),
  getMyLoans: () => api.get("/api/loans/my"),
  getLoanById: (id: string) => api.get(`/api/users/me/loans/${id}`),
  getInstallments: (loanId: string) =>
    api.get(`/api/loans/${loanId}/installments`),
  payInstallment: (installmentId: string) =>
    api.post("/api/loans/installment/pay", { installmentId }),
};

// ─── Notification API (User) ─────────────────────────────────────────────────
export const notificationApi = {
  getAll: (params?: { page?: number; size?: number }) =>
    api.get("/api/users/me/notifications", { params }),
  markRead: (id: string) => api.put(`/api/users/me/notifications/${id}/read`),
  markAllRead: () => api.put("/api/users/me/notifications/read-all"),
  getUnreadCount: () => api.get("/api/users/me/notifications/unread-count"),
};

// ─── Admin API ───────────────────────────────────────────────────────────────
export const adminApi = {
  // Loans
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
  getLoanById: (loanId: string) => api.get(`/api/admin/loans/${loanId}`),
  decideLoan: (loanId: string, data: { decision: string; note?: string }) =>
    api.post(`/api/admin/loans/${loanId}/decide`, data),
  deleteLoan: (loanId: string) => api.delete(`/api/admin/loans/${loanId}`),
  updateLoanNote: (loanId: string, adminNote: string) =>
    api.put(`/api/admin/loans/${loanId}/note`, { adminNote }),
  bulkApprove: (loanIds: string[], note?: string) =>
    api.post("/api/admin/loans/bulk-approve", { loanIds, note }),
  bulkReject: (loanIds: string[], note: string) =>
    api.post("/api/admin/loans/bulk-reject", { loanIds, note }),
  exportLoans: () =>
    api.get("/api/admin/loans/export", { responseType: "blob" }),

  // Users
  getUsers: (params?: {
    page?: number;
    size?: number;
    search?: string;
    status?: string;
  }) => api.get("/api/admin/users", { params }),
  getUserProfile: (userId: number | string) =>
    api.get(`/api/admin/users/${userId}`),
  createUser: (data: { username: string; email: string; role: string }) =>
    api.post("/api/admin/users", data),
  updateUser: (
    userId: number | string,
    data: { username?: string; email?: string; isActive?: boolean },
  ) => api.put(`/api/admin/users/${userId}`, data),
  deactivateUser: (userId: number | string) =>
    api.put(`/api/admin/users/${userId}/deactivate`),
  reactivateUser: (userId: number | string) =>
    api.put(`/api/admin/users/${userId}/reactivate`),
  getUserLoans: (userId: number | string) =>
    api.get(`/api/admin/users/${userId}/loans`),
  getUserTransactions: (
    userId: number | string,
    params?: { page?: number; size?: number; type?: string },
  ) => api.get(`/api/admin/users/${userId}/transactions`, { params }),
  exportUsers: () =>
    api.get("/api/admin/users/export", { responseType: "blob" }),

  // Analytics
  getAnalytics: () => api.get("/api/admin/analytics"),
  getAnalyticsSummary: () => api.get("/api/admin/analytics/summary"),
  getUserGrowth: () => api.get("/api/admin/analytics/user-growth"),
  exportAnalytics: () =>
    api.get("/api/admin/analytics/export", { responseType: "blob" }),

  // Audit Logs
  getAuditLogs: (params?: {
    page?: number;
    size?: number;
    action?: string;
    from?: string;
    to?: string;
  }) => api.get("/api/admin/audit-logs", { params }),

  // Notifications
  sendNotificationToUser: (
    userId: number | string,
    data: { title: string; message: string },
  ) => api.post(`/api/admin/notifications/user/${userId}`, data),
  broadcastNotification: (data: { title: string; message: string }) =>
    api.post("/api/admin/notifications/broadcast", data),
  getAdminNotifications: (params?: { page?: number; size?: number }) =>
    api.get("/api/admin/notifications", { params }),
  deleteNotification: (id: string) =>
    api.delete(`/api/admin/notifications/${id}`),

  // Installments
  getAllInstallments: (params?: {
    page?: number;
    size?: number;
    status?: string;
    loanId?: string;
    search?: string;
  }) => api.get("/api/admin/installments", { params }),
  getLoanInstallments: (loanId: string) =>
    api.get(`/api/admin/loans/${loanId}/installments`),
  markInstallmentPaid: (installmentId: string) =>
    api.put(`/api/admin/installments/${installmentId}/mark-paid`),
  markInstallmentOverdue: (installmentId: string) =>
    api.put(`/api/admin/installments/${installmentId}/mark-overdue`),
  markInstallmentPending: (installmentId: string) =>
    api.put(`/api/admin/installments/${installmentId}/mark-pending`),
  triggerPaymentReminders: (daysAhead?: number) =>
    api.post("/api/admin/installments/trigger-reminders", null, {
      params: { daysAhead: daysAhead ?? 3 },
    }),

  // Transactions (Admin)
  getAllTransactions: (params?: {
    page?: number;
    size?: number;
    type?: string;
    from?: string;
    to?: string;
    userId?: string;
    search?: string;
  }) => api.get("/api/admin/transactions", { params }),
  deleteTransaction: (id: string) =>
    api.delete(`/api/admin/transactions/${id}`),

  // User extra actions
  resetUserPassword: (userId: number | string) =>
    api.put(`/api/admin/users/${userId}/reset-password`),
  deleteUser: (userId: number | string) =>
    api.delete(`/api/admin/users/${userId}`),
};

// ─── Dashboard API ───────────────────────────────────────────────────────────
export const dashboardApi = {
  getSummary: () => api.get("/api/dashboard/summary"),
};

export default api;
