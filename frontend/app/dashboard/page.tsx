"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../context/AuthContext";
import Sidebar from "../../components/Sidebar";
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

        {dataError && <ErrorAlert message={dataError} />}

        {/* Stat Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-5 mb-8">
          <StatCard
            label="Total Income"
            value={formatCurrency(totalIncome)}
            icon={
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
            }
            iconBg="gradient-emerald"
            valueColor="text-emerald-600"
          />
          <StatCard
            label="Total Expenses"
            value={formatCurrency(totalExpense)}
            icon={
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
            }
            iconBg="gradient-rose"
            valueColor="text-red-500"
          />
          <StatCard
            label="Savings Balance"
            value={formatCurrency(savingsBalance)}
            icon={
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
            }
            iconBg="gradient-sky"
            valueColor={
              Number(savingsBalance) >= 0 ? "text-sky-600" : "text-red-500"
            }
          />
          <StatCard
            label="Loan Applications"
            value={String(summary?.totalLoans ?? loans.length)}
            sub={`${pendingLoans} pending · ${approvedLoans} approved`}
            icon={
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
            }
            iconBg="gradient-amber"
            valueColor="text-slate-900"
          />
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
              <RiskBadge
                level={summary.currentRiskLevel as "LOW" | "MEDIUM" | "HIGH"}
                score={summary.currentRiskScore ?? undefined}
              />
            ) : (
              <p className="text-slate-400 text-sm">No loan applied yet</p>
            )}
          </div>
        </div>

        {/* Latest Loan */}
        {latestLoan && <LatestLoan loan={latestLoan} />}

        {/* Bottom grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <QuickActions actions={quickActions} />
          <RecentTransactions transactions={transactions} />
        </div>
      </main>
    </div>
  );
}
