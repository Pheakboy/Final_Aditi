"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../context/AuthContext";
import Sidebar from "../../components/Sidebar";
import RiskBadge from "../../components/RiskBadge";
import { transactionApi, loanApi } from "../../services/api";
import { Transaction, Loan } from "../../types";
import { formatCurrency } from "../../utils/format";

export default function DashboardPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [loans, setLoans] = useState<Loan[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");

  useEffect(() => {
    if (!isLoading && !user) {
      router.push("/login");
    }
    if (!isLoading && isAdmin) {
      router.push("/admin/dashboard");
    }
  }, [user, isLoading, isAdmin, router]);

  useEffect(() => {
    if (user && !isAdmin) {
      setDataLoading(true);
      const fetchData = async () => {
        try {
          const [txRes, loanRes] = await Promise.all([
            transactionApi.getAll(),
            loanApi.getMyLoans(),
          ]);
          setTransactions(txRes.data.data || []);
          setLoans(loanRes.data.data || []);
          setDataError("");
        } catch (err) {
          console.error("Failed to fetch dashboard data", err);
          setDataError("Failed to load dashboard data. Please refresh the page.");
        } finally {
          setDataLoading(false);
        }
      };
      fetchData();
    }
  }, [user, isAdmin]);

  if (isLoading || dataLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const totalIncome = transactions
    .filter((t) => t.type === "INCOME")
    .reduce((sum, t) => sum + t.amount, 0);

  const totalExpense = transactions
    .filter((t) => t.type === "EXPENSE")
    .reduce((sum, t) => sum + t.amount, 0);

  const latestLoan = loans[0];
  const pendingLoans = loans.filter((l) => l.status === "PENDING").length;
  const approvedLoans = loans.filter((l) => l.status === "APPROVED").length;

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-500 mt-1">Welcome back, {user?.username}!</p>
        </div>

        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-6">
            {dataError}
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm text-gray-500">Total Transactions</p>
              <div className="bg-blue-100 rounded-lg p-2">
                <svg
                  className="w-4 h-4 text-blue-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                  />
                </svg>
              </div>
            </div>
            <p className="text-2xl font-bold text-gray-900">
              {transactions.length}
            </p>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm text-gray-500">Total Income</p>
              <div className="bg-green-100 rounded-lg p-2">
                <svg
                  className="w-4 h-4 text-green-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M7 11l5-5m0 0l5 5m-5-5v12"
                  />
                </svg>
              </div>
            </div>
            <p className="text-2xl font-bold text-green-600">
              {formatCurrency(totalIncome)}
            </p>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm text-gray-500">Total Expenses</p>
              <div className="bg-red-100 rounded-lg p-2">
                <svg
                  className="w-4 h-4 text-red-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M17 13l-5 5m0 0l-5-5m5 5V6"
                  />
                </svg>
              </div>
            </div>
            <p className="text-2xl font-bold text-red-600">
              {formatCurrency(totalExpense)}
            </p>
          </div>

          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-2">
              <p className="text-sm text-gray-500">Loan Applications</p>
              <div className="bg-purple-100 rounded-lg p-2">
                <svg
                  className="w-4 h-4 text-purple-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
              </div>
            </div>
            <p className="text-2xl font-bold text-gray-900">{loans.length}</p>
            <p className="text-xs text-gray-400 mt-1">
              {pendingLoans} pending · {approvedLoans} approved
            </p>
          </div>
        </div>

        {/* Latest Loan Risk Score */}
        {latestLoan && (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6 mb-8">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">
              Latest Loan Application
            </h2>
            <div className="flex items-center justify-between">
              <div>
                <p className="text-3xl font-bold text-gray-900">
                  {formatCurrency(latestLoan.loanAmount)}
                </p>
                <p className="text-sm text-gray-500 mt-1">
                  Status:{" "}
                  <span
                    className={`font-medium ${latestLoan.status === "APPROVED" ? "text-green-600" : latestLoan.status === "REJECTED" ? "text-red-600" : "text-yellow-600"}`}
                  >
                    {latestLoan.status}
                  </span>
                </p>
              </div>
              <div className="text-right">
                <RiskBadge
                  level={latestLoan.riskLevel}
                  score={latestLoan.riskScore}
                />
                {latestLoan.riskScore && (
                  <p className="text-sm text-gray-500 mt-2">
                    Risk Score: {latestLoan.riskScore.toFixed(1)}/100
                  </p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Quick Actions */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">
              Quick Actions
            </h2>
            <div className="space-y-3">
              <Link
                href="/transactions"
                className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors"
              >
                <div className="bg-blue-100 rounded-lg p-2">
                  <svg
                    className="w-4 h-4 text-blue-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 4v16m8-8H4"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-900">
                    Add Transaction
                  </p>
                  <p className="text-xs text-gray-500">
                    Record income or expense
                  </p>
                </div>
              </Link>
              <Link
                href="/loan/apply"
                className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors"
              >
                <div className="bg-green-100 rounded-lg p-2">
                  <svg
                    className="w-4 h-4 text-green-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-900">
                    Apply for Loan
                  </p>
                  <p className="text-xs text-gray-500">
                    Submit a new loan application
                  </p>
                </div>
              </Link>
              <Link
                href="/loan/status"
                className="flex items-center gap-3 p-3 rounded-lg border border-gray-200 hover:bg-gray-50 transition-colors"
              >
                <div className="bg-purple-100 rounded-lg p-2">
                  <svg
                    className="w-4 h-4 text-purple-600"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                    />
                  </svg>
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-900">
                    View Loan Status
                  </p>
                  <p className="text-xs text-gray-500">
                    Check your loan applications
                  </p>
                </div>
              </Link>
            </div>
          </div>

          {/* Recent Transactions */}
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-900">
                Recent Transactions
              </h2>
              <Link
                href="/transactions"
                className="text-sm text-blue-600 hover:text-blue-700"
              >
                View all
              </Link>
            </div>
            {transactions.length === 0 ? (
              <p className="text-sm text-gray-500 text-center py-4">
                No transactions yet
              </p>
            ) : (
              <div className="space-y-3">
                {transactions.slice(0, 5).map((tx) => (
                  <div
                    key={tx.id}
                    className="flex items-center justify-between"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`w-8 h-8 rounded-full flex items-center justify-center ${tx.type === "INCOME" ? "bg-green-100" : "bg-red-100"}`}
                      >
                        <svg
                          className={`w-4 h-4 ${tx.type === "INCOME" ? "text-green-600" : "text-red-600"}`}
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          {tx.type === "INCOME" ? (
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M7 11l5-5m0 0l5 5m-5-5v12"
                            />
                          ) : (
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M17 13l-5 5m0 0l-5-5m5 5V6"
                            />
                          )}
                        </svg>
                      </div>
                      <div>
                        <p className="text-sm font-medium text-gray-900">
                          {tx.description || tx.type}
                        </p>
                        <p className="text-xs text-gray-400">
                          {new Date(tx.transactionDate).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    <span
                      className={`text-sm font-semibold ${tx.type === "INCOME" ? "text-green-600" : "text-red-600"}`}
                    >
                      {tx.type === "INCOME" ? "+" : "-"}
                      {formatCurrency(tx.amount)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
