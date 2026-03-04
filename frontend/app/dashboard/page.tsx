"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../context/AuthContext";
import Sidebar from "../../components/Sidebar";
import RiskBadge from "../../components/RiskBadge";
import { transactionApi, loanApi, dashboardApi } from "../../services/api";
import { Transaction, Loan, DashboardSummary } from "../../types";
import { formatCurrency, formatDate } from "../../utils/format";

export default function DashboardPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [loans, setLoans] = useState<Loan[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
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
          const [txRes, loanRes, summaryRes] = await Promise.all([
            transactionApi.getAll(),
            loanApi.getMyLoans(),
            dashboardApi.getSummary(),
          ]);
          setTransactions(txRes.data.data || []);
          setLoans(loanRes.data.data || []);
          setSummary(summaryRes.data.data || null);
          setDataError("");
        } catch (err) {
          console.error("Failed to fetch dashboard data", err);
          setDataError(
            "Failed to load dashboard data. Please refresh the page.",
          );
        } finally {
          setDataLoading(false);
        }
      };
      fetchData();
    }
  }, [user, isAdmin]);

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent"></div>
      </div>
    );
  }

  const latestLoan = loans[0];

  // Use server-computed summary values when available, fall back to client computation
  const totalIncome =
    summary?.totalIncome ??
    transactions
      .filter((t) => t.type === "INCOME")
      .reduce((sum, t) => sum + t.amount, 0);
  const totalExpense =
    summary?.totalExpenses ??
    transactions
      .filter((t) => t.type === "EXPENSE")
      .reduce((sum, t) => sum + t.amount, 0);
  const savingsBalance =
    summary?.savingsBalance ?? Number(totalIncome) - Number(totalExpense);
  const avgMonthlyIncome = summary?.averageMonthlyIncome ?? 0;
  const pendingLoans =
    summary?.pendingLoans ?? loans.filter((l) => l.status === "PENDING").length;
  const approvedLoans =
    summary?.approvedLoans ??
    loans.filter((l) => l.status === "APPROVED").length;

  const statCards = [
    {
      label: "Total Income",
      value: formatCurrency(totalIncome),
      icon: (
        <svg
          className="w-5 h-5 text-white"
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
      ),
      iconBg: "gradient-emerald",
      valueColor: "text-emerald-600",
    },
    {
      label: "Total Expenses",
      value: formatCurrency(totalExpense),
      icon: (
        <svg
          className="w-5 h-5 text-white"
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
      ),
      iconBg: "gradient-rose",
      valueColor: "text-red-500",
    },
    {
      label: "Savings Balance",
      value: formatCurrency(savingsBalance),
      icon: (
        <svg
          className="w-5 h-5 text-white"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"
          />
        </svg>
      ),
      iconBg: "gradient-sky",
      valueColor: Number(savingsBalance) >= 0 ? "text-sky-600" : "text-red-500",
    },
    {
      label: "Loan Applications",
      value: String(summary?.totalLoans ?? loans.length),
      sub: `${pendingLoans} pending · ${approvedLoans} approved`,
      icon: (
        <svg
          className="w-5 h-5 text-white"
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
      ),
      iconBg: "gradient-amber",
      valueColor: "text-slate-900",
    },
  ];

  const quickActions = [
    {
      href: "/transactions",
      icon: (
        <svg
          className="w-4 h-4 text-teal-600"
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
      ),
      iconBg: "bg-teal-50",
      title: "Add Transaction",
      sub: "Record income or expense",
    },
    {
      href: "/loan/apply",
      icon: (
        <svg
          className="w-4 h-4 text-emerald-600"
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
      ),
      iconBg: "bg-emerald-50",
      title: "Apply for Loan",
      sub: "Submit a new loan application",
    },
    {
      href: "/loan/status",
      icon: (
        <svg
          className="w-4 h-4 text-indigo-600"
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
      ),
      iconBg: "bg-indigo-50",
      title: "View Loan Status",
      sub: "Check your loan applications",
    },
  ];

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-8 overflow-auto">
        {/* Header */}
        <div className="mb-8 animate-fade-in">
          <h1 className="text-2xl font-bold text-slate-900">Dashboard</h1>
          <p className="text-slate-500 mt-1 text-sm">
            Welcome back,{" "}
            <span className="font-semibold text-teal-600">
              {user?.username}
            </span>
            !
          </p>
        </div>

        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-6 flex items-center gap-2">
            <svg
              className="w-4 h-4 shrink-0"
              fill="currentColor"
              viewBox="0 0 20 20"
            >
              <path
                fillRule="evenodd"
                d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                clipRule="evenodd"
              />
            </svg>
            {dataError}
          </div>
        )}

        {/* Stat Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5 mb-8">
          {statCards.map((card) => (
            <div
              key={card.label}
              className="bg-white rounded-2xl card-shadow p-5 flex items-start gap-4"
            >
              <div
                className={`${card.iconBg} w-10 h-10 rounded-xl flex items-center justify-center shrink-0`}
              >
                {card.icon}
              </div>
              <div className="min-w-0">
                <p className="text-xs text-slate-500 mb-0.5">{card.label}</p>
                <p className={`text-xl font-bold truncate ${card.valueColor}`}>
                  {card.value}
                </p>
                {card.sub && (
                  <p className="text-xs text-slate-400 mt-0.5">{card.sub}</p>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Secondary stats row */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-8">
          <div className="bg-white rounded-2xl card-shadow p-5">
            <p className="text-xs text-slate-500 mb-1">Avg. Monthly Income</p>
            <p className="text-xl font-bold text-slate-900">
              {formatCurrency(avgMonthlyIncome)}
            </p>
            <p className="text-xs text-slate-400 mt-0.5">
              Across active months
            </p>
          </div>
          <div className="bg-white rounded-2xl card-shadow p-5">
            <p className="text-xs text-slate-500 mb-1">Transactions</p>
            <p className="text-xl font-bold text-slate-900">
              {summary?.totalTransactions ?? transactions.length}
            </p>
            <p className="text-xs text-slate-400 mt-0.5">Total recorded</p>
          </div>
          <div className="bg-white rounded-2xl card-shadow p-5">
            <p className="text-xs text-slate-500 mb-2">Current Risk Level</p>
            {summary?.currentRiskLevel ? (
              <>
                <RiskBadge
                  level={summary.currentRiskLevel as "LOW" | "MEDIUM" | "HIGH"}
                  score={summary.currentRiskScore ?? undefined}
                />
              </>
            ) : (
              <p className="text-slate-400 text-sm">No loan applied yet</p>
            )}
          </div>
        </div>

        {/* Latest Loan */}
        {latestLoan && (
          <div className="bg-white rounded-2xl card-shadow p-5 mb-8">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-slate-900">
                Latest Loan Application
              </h2>
              <Link
                href="/loan/status"
                className="text-xs font-medium text-teal-600 hover:text-teal-700"
              >
                View all →
              </Link>
            </div>
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="text-2xl font-bold text-slate-900">
                  {formatCurrency(latestLoan.loanAmount)}
                </p>
                {latestLoan.purpose && (
                  <p className="text-sm text-slate-400 mt-0.5">
                    {latestLoan.purpose}
                  </p>
                )}
                <div className="flex items-center gap-2 mt-2">
                  <span
                    className={`text-xs font-semibold px-2 py-0.5 rounded-full ${latestLoan.status === "APPROVED" ? "bg-emerald-50 text-emerald-700" : latestLoan.status === "REJECTED" ? "bg-red-50 text-red-700" : "bg-amber-50 text-amber-700"}`}
                  >
                    {latestLoan.status}
                  </span>
                </div>
                {latestLoan.adminNote && (
                  <p className="text-sm text-slate-500 mt-2 italic">
                    &ldquo;{latestLoan.adminNote}&rdquo;
                  </p>
                )}
              </div>
              <RiskBadge
                level={latestLoan.riskLevel}
                score={latestLoan.riskScore}
              />
            </div>
          </div>
        )}

        {/* Bottom grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Quick Actions */}
          <div className="bg-white rounded-2xl card-shadow p-5">
            <h2 className="text-sm font-semibold text-slate-900 mb-4">
              Quick Actions
            </h2>
            <div className="space-y-2">
              {quickActions.map((action) => (
                <Link
                  key={action.href}
                  href={action.href}
                  className="flex items-center gap-3 p-3 rounded-xl border border-slate-100 hover:border-teal-200 hover:bg-teal-50/50 transition-colors group"
                >
                  <div
                    className={`${action.iconBg} w-9 h-9 rounded-lg flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform`}
                  >
                    {action.icon}
                  </div>
                  <div>
                    <p className="text-sm font-medium text-slate-800">
                      {action.title}
                    </p>
                    <p className="text-xs text-slate-400">{action.sub}</p>
                  </div>
                  <svg
                    className="w-4 h-4 text-slate-300 ml-auto"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M9 5l7 7-7 7"
                    />
                  </svg>
                </Link>
              ))}
            </div>
          </div>

          {/* Recent Transactions */}
          <div className="bg-white rounded-2xl card-shadow p-5">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-semibold text-slate-900">
                Recent Transactions
              </h2>
              <Link
                href="/transactions"
                className="text-xs font-medium text-teal-600 hover:text-teal-700"
              >
                View all →
              </Link>
            </div>
            {transactions.length === 0 ? (
              <div className="text-center py-8">
                <div className="w-10 h-10 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
                  <svg
                    className="w-5 h-5 text-slate-400"
                    fill="none"
                    viewBox="0 0 24 24"
                    stroke="currentColor"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={1.5}
                      d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                    />
                  </svg>
                </div>
                <p className="text-sm text-slate-400">No transactions yet</p>
              </div>
            ) : (
              <div className="space-y-1">
                {transactions.slice(0, 5).map((tx) => (
                  <div key={tx.id} className="flex items-center gap-3 py-2">
                    <div
                      className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${tx.type === "INCOME" ? "bg-emerald-50" : "bg-red-50"}`}
                    >
                      <svg
                        className={`w-4 h-4 ${tx.type === "INCOME" ? "text-emerald-500" : "text-red-400"}`}
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
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-slate-800 truncate">
                        {tx.description || tx.type}
                      </p>
                      <p className="text-xs text-slate-400">
                        {formatDate(tx.transactionDate)}
                      </p>
                    </div>
                    <span
                      className={`text-sm font-semibold shrink-0 ${tx.type === "INCOME" ? "text-emerald-600" : "text-red-500"}`}
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
