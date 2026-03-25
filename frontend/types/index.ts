export interface User {
  email: string;
  username: string;
  roles: string[];
  photo?: string;
  phoneNumber?: string;
  address?: string;
  bio?: string;
}

export interface AuthResponse {
  type: string;
  accessToken: string;
  refreshToken: string;
  roles: string[];
}

export interface Transaction {
  id: string;
  type: "INCOME" | "EXPENSE";
  amount: number;
  description?: string;
  transactionDate: string;
  createdAt: string;
}

export interface Loan {
  id: string;
  loanAmount: number;
  monthlyIncome: number;
  monthlyExpense: number;
  riskScore?: number;
  riskLevel?: "LOW" | "MEDIUM" | "HIGH";
  status: "PENDING" | "APPROVED" | "REJECTED" | "ACTIVE" | "COMPLETED";
  purpose?: string;
  adminNote?: string;
  interestRate?: number;
  termMonths?: number;
  startDate?: string;
  monthlyPayment?: number;
  createdAt: string;
  updatedAt: string;
  applicantEmail?: string;
  applicantUsername?: string;
}

export interface LoanInstallment {
  id: string;
  installmentNumber: number;
  dueDate: string;
  principalAmount: number;
  interestAmount: number;
  totalAmount: number;
  status: "PENDING" | "PAID" | "OVERDUE";
  paidAt?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  message: string;
  data: T;
}

export interface PagedResponse<T> {
  content: T[];
  page: number;
  size: number;
  totalElements: number;
  totalPages: number;
  last: boolean;
}

export interface AdminUser {
  id: number;
  username: string;
  email: string;
  roles: string[];
  phoneNumber?: string;
  address?: string;
  enabled: boolean;
}

export interface UserProfile {
  id: number;
  username: string;
  email: string;
  phoneNumber?: string;
  address?: string;
  bio?: string;
  enabled: boolean;
  roles: string[];
  totalIncome: number;
  totalExpenses: number;
  savingsBalance: number;
  totalTransactions: number;
  latestRiskScore?: number;
  latestRiskLevel?: "LOW" | "MEDIUM" | "HIGH";
  loans: Loan[];
  recentTransactions: Transaction[];
}

export interface AuditLog {
  id: number;
  action: string;
  performedBy: string;
  targetType?: string;
  details?: string;
  ipAddress?: string;
  timestamp: string;
}

export interface Notification {
  id: string;
  title: string;
  message: string;
  type:
    | "LOAN_APPROVED"
    | "LOAN_REJECTED"
    | "LOAN_REMINDER"
    | "INSTALLMENT_PAID"
    | "BROADCAST"
    | "GENERAL";
  isRead: boolean;
  createdAt: string;
}

export interface AnalyticsData {
  riskDistribution: {
    low: number;
    medium: number;
    high: number;
    total: number;
  };
  approvalRate: {
    approved: number;
    rejected: number;
    pending: number;
    total: number;
    approvalPercentage: number;
    rejectionPercentage: number;
  };
  monthlyStats: Array<{
    year: number;
    month: number;
    count: number;
  }>;
  topHighRiskUsers: Array<{
    email: string;
    username: string;
    riskScore: number;
  }>;
}

export interface DashboardSummary {
  totalIncome: number;
  totalExpenses: number;
  savingsBalance: number;
  averageMonthlyIncome: number;
  totalTransactions: number;
  currentRiskScore?: number;
  currentRiskLevel?: "LOW" | "MEDIUM" | "HIGH";
  totalLoans: number;
  pendingLoans: number;
  approvedLoans: number;
  rejectedLoans: number;
}
