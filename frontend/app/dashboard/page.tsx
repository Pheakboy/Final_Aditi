"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../context/AuthContext";
import UserLayout from "../../components/UserLayout";
import RiskBadge from "../../components/RiskBadge";
import LoadingScreen from "../../components/ui/LoadingScreen";
import ErrorAlert from "../../components/ui/ErrorAlert";
import StatCard from "../../components/ui/StatCard";
import LatestLoan from "../../components/dashboard/LatestLoan";
import QuickActions from "../../components/dashboard/QuickActions";
import RecentTransactions from "../../components/dashboard/RecentTransactions";
import { transactionApi, loanApi, dashboardApi } from "../../services/api";
import { Transaction, Loan, DashboardSummary } from "../../types";
import { formatCurrency } from "../../utils/format";

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

  const fetchData = useCallback(async () => {
    if (!user || isAdmin) return;
    setDataLoading(true);
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
    } catch {
      setDataError("Failed to load dashboard data. Please refresh the page.");
    } finally {
      setDataLoading(false);
    }
  }, [user, isAdmin]);

  useEffect(() => {
    if (user && !isAdmin) fetchData();
  }, [user, isAdmin, fetchData]);

  if (isLoading) {
    return <LoadingScreen color="border-teal-500" />;
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
    <UserLayout title="Dashboard" onRefresh={fetchData}>
      <div className="p-6 lg:p-10">
        {dataError && <ErrorAlert message={dataError} />}

        {/* Stat Cards - Primary Metrics */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
          {dataLoading ? (
            Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="bg-white border border-slate-200 rounded-xl shadow-sm p-5 flex flex-col justify-between gap-4 animate-pulse"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 space-y-2">
                    <div className="h-3 bg-slate-200 rounded w-24"></div>
                    <div className="h-8 bg-slate-200 rounded w-32"></div>
                    <div className="h-3 bg-slate-200 rounded w-20"></div>
                  </div>
                  <div className="w-10 h-10 bg-slate-200 rounded-lg shrink-0"></div>
                </div>
              </div>
            ))
          ) : (
            <>
              <StatCard
                label="Total Income"
                value={formatCurrency(totalIncome)}
                icon={
                  <svg
                    className="w-7 h-7 text-teal-500"
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
                }
                iconBg="gradient-emerald"
                valueColor="text-emerald-700"
              />
              <StatCard
                label="Total Expenses"
                value={formatCurrency(totalExpense)}
                icon={
                  <svg
                    className="w-7 h-7 text-rose-500"
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
                }
                iconBg="gradient-rose"
                valueColor="text-rose-700"
              />
              <StatCard
                label="Savings Balance"
                value={formatCurrency(savingsBalance)}
                icon={
                  <svg
                    className="w-7 h-7 text-sky-500"
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
                }
                iconBg="gradient-sky"
                valueColor={
                  Number(savingsBalance) >= 0 ? "text-sky-700" : "text-rose-700"
                }
              />
              <StatCard
                label="Loan Applications"
                value={String(summary?.totalLoans ?? loans.length)}
                sub={`${pendingLoans} pending · ${approvedLoans} approved`}
                icon={
                  <svg
                    className="w-7 h-7 text-amber-500"
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
                }
                iconBg="gradient-amber"
                valueColor="text-amber-700"
              />
            </>
          )}
        </div>

        {/* Performance & Risk (Secondary Stats) */}
        <div className="mb-4 mt-8 flex items-center justify-between">
          <h2 className="text-xl font-bold text-slate-800 tracking-tight">
            Performance & Risk
          </h2>
          <div className="h-px bg-slate-200/60 flex-1 ml-6"></div>
        </div>

        <div
          className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10 animate-slide-up"
          style={{ animationDelay: "100ms" }}
        >
          {dataLoading ? (
            Array.from({ length: 3 }).map((_, i) => (
              <div
                key={i}
                className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 animate-pulse"
              >
                <div className="h-3 bg-slate-200 rounded w-20 mb-3"></div>
                <div className="h-7 bg-slate-200 rounded w-32"></div>
              </div>
            ))
          ) : (
            <>
              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 relative overflow-hidden transition-all hover:shadow-md">
                <div className="relative z-10">
                  <p className="text-xs font-bold text-slate-500 mb-1 uppercase tracking-wider">
                    Avg. Monthly
                  </p>
                  <p className="text-2xl font-extrabold text-slate-900 tracking-tight">
                    {formatCurrency(avgMonthlyIncome)}
                  </p>
                </div>
                <div className="absolute -bottom-6 -right-6 w-24 h-24 bg-emerald-50 rounded-full opacity-50"></div>
              </div>

              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 relative overflow-hidden transition-all hover:shadow-md">
                <div className="relative z-10">
                  <p className="text-xs font-bold text-slate-500 mb-1 uppercase tracking-wider">
                    Transactions
                  </p>
                  <div className="flex items-baseline gap-2">
                    <p className="text-2xl font-extrabold text-slate-900 tracking-tight">
                      {summary?.totalTransactions ?? transactions.length}
                    </p>
                    <span className="text-xs font-semibold text-slate-500">
                      recorded
                    </span>
                  </div>
                </div>
                <div className="absolute -bottom-6 -right-6 w-24 h-24 bg-sky-50 rounded-full opacity-50"></div>
              </div>

              <div className="bg-white rounded-xl border border-slate-200 shadow-sm p-6 relative overflow-hidden transition-all hover:shadow-md">
                <div className="relative z-10">
                  <p className="text-xs font-bold text-slate-500 mb-2 uppercase tracking-wider">
                    Risk Level
                  </p>
                  <div className="mt-0.5">
                    {summary?.currentRiskLevel ? (
                      <RiskBadge
                        level={
                          summary.currentRiskLevel as "LOW" | "MEDIUM" | "HIGH"
                        }
                        score={summary.currentRiskScore ?? undefined}
                      />
                    ) : (
                      <p className="text-slate-500 text-xs font-semibold bg-slate-50 inline-block px-2.5 py-1 rounded-md border border-slate-200">
                        No data
                      </p>
                    )}
                  </div>
                </div>
                <div className="absolute -bottom-6 -right-6 w-24 h-24 bg-indigo-50 rounded-full opacity-50"></div>
              </div>
            </>
          )}
        </div>

        {/* Action Center Divider */}
        <div className="mb-4 mt-8 flex items-center justify-between">
          <h2 className="text-xl font-bold text-slate-800 tracking-tight">
            Action Center
          </h2>
          <div className="h-px bg-slate-200/60 flex-1 ml-6"></div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 space-y-6">
            {/* Latest Loan */}
            {dataLoading ? (
              <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-6 animate-pulse">
                <div className="flex items-center justify-between mb-6">
                  <div className="h-4 bg-slate-200 rounded w-40"></div>
                  <div className="h-6 bg-slate-200 rounded w-16"></div>
                </div>
                <div className="h-8 bg-slate-200 rounded w-32 mb-2"></div>
                <div className="h-3 bg-slate-200 rounded w-48 mb-3"></div>
                <div className="h-5 bg-slate-200 rounded-full w-16"></div>
              </div>
            ) : latestLoan ? (
              <LatestLoan loan={latestLoan} />
            ) : null}
            <RecentTransactions
              transactions={transactions}
              isLoading={dataLoading}
            />
          </div>
          <div className="lg:col-span-1">
            <QuickActions actions={quickActions} />
          </div>
        </div>
      </div>
    </UserLayout>
  );
}
