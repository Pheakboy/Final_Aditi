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
  status: "PENDING" | "APPROVED" | "REJECTED";
  purpose?: string;
  adminNote?: string;
  createdAt: string;
  updatedAt: string;
  applicantEmail?: string;
  applicantUsername?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  message: string;
  data: T;
}
