"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import UserLayout from "../../../components/UserLayout";
import RiskBadge from "../../../components/RiskBadge";
import { loanApi } from "../../../services/api";
import { Loan } from "../../../types";
import { formatCurrency, formatDate } from "../../../utils/format";

export default function LoanStatusPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [loans, setLoans] = useState<Loan[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [filter, setFilter] = useState<
    "ALL" | "PENDING" | "APPROVED" | "REJECTED" | "ACTIVE" | "COMPLETED"
  >("ALL");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
  }, [user, isLoading, router]);

  useEffect(() => {
    if (user) {
      setDataLoading(true);
      loanApi
        .getMyLoans()
        .then((res) => setLoans(res.data.data || []))
        .catch(() =>
          setDataError("Failed to load loan applications. Please refresh."),
        )
        .finally(() => setDataLoading(false));
    }
  }, [user]);

  const filteredLoans =
    filter === "ALL" ? loans : loans.filter((l) => l.status === filter);

  const statusConfig: Record<string, { bg: string; badge: string }> = {
    PENDING: {
      bg: "bg-amber-50 border-amber-200 text-amber-700",
      badge: "bg-amber-100 text-amber-700",
    },
    APPROVED: {
      bg: "bg-emerald-50 border-emerald-200 text-emerald-700",
      badge: "bg-emerald-100 text-emerald-700",
    },
    REJECTED: {
      bg: "bg-red-50 border-red-200 text-red-700",
      badge: "bg-red-100 text-red-700",
    },
    ACTIVE: {
      bg: "bg-blue-50 border-blue-200 text-blue-700",
      badge: "bg-blue-100 text-blue-700",
    },
    COMPLETED: {
      bg: "bg-slate-50 border-slate-200 text-slate-600",
      badge: "bg-slate-100 text-slate-600",
    },
  };

  if (isLoading)
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent" />
      </div>
    );

  return (
    <UserLayout
      title="My Loans"
      subtitle="Track your loan applications and decisions"
    >
      <div className="p-6 lg:p-8">
        {/* Action bar */}
        <div className="flex justify-end mb-8 animate-fade-in">
          <Link
            href="/loan/apply"
            className="flex items-center gap-2 px-4 py-2 gradient-teal text-white text-sm font-semibold rounded-xl shadow-sm hover:opacity-90 transition-all"
          >
            <svg
              className="w-4 h-4"
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
            New Application
          </Link>
        </div>

        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-6">
            {dataError}
          </div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-3 sm:grid-cols-5 gap-4 mb-8">
          {(
            ["PENDING", "APPROVED", "REJECTED", "ACTIVE", "COMPLETED"] as const
          ).map((status) => {
            const count = loans.filter((l) => l.status === status).length;
            const cfg = statusConfig[status];
            return (
              <div key={status} className={`border rounded-2xl p-5 ${cfg.bg}`}>
                <p className="text-xs font-semibold uppercase tracking-wide mb-1">
                  {status}
                </p>
                <p className="text-3xl font-bold">{count}</p>
                <p className="text-xs mt-1 opacity-70">
                  application{count !== 1 ? "s" : ""}
                </p>
              </div>
            );
          })}
        </div>

        {/* Filter Tabs */}
        <div className="flex flex-wrap gap-2 mb-6">
          {(
            [
              "ALL",
              "PENDING",
              "APPROVED",
              "REJECTED",
              "ACTIVE",
              "COMPLETED",
            ] as const
          ).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-4 py-2 text-sm font-medium rounded-xl transition-all ${filter === f ? "gradient-teal text-white shadow-sm" : "bg-white text-slate-600 border border-slate-200 hover:bg-slate-50"}`}
            >
              {f} (
              {f === "ALL"
                ? loans.length
                : loans.filter((l) => l.status === f).length}
              )
            </button>
          ))}
        </div>

        {/* Loans */}
        {dataLoading ? (
          <div className="flex justify-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-2 border-teal-500 border-t-transparent" />
          </div>
        ) : filteredLoans.length === 0 ? (
          <div className="bg-white rounded-2xl card-shadow p-12 text-center">
            <div className="w-12 h-12 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
              <svg
                className="w-6 h-6 text-slate-400"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={1.5}
                  d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            </div>
            <p className="text-slate-500 text-sm mb-3">
              {filter === "ALL"
                ? "No loan applications yet."
                : `No ${filter.toLowerCase()} loans.`}
            </p>
            <Link
              href="/loan/apply"
              className="text-teal-600 hover:text-teal-700 text-sm font-medium"
            >
              Apply for your first loan →
            </Link>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredLoans.map((loan) => (
              <div
                key={loan.id}
                className="bg-white rounded-2xl card-shadow p-5 hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 mb-2">
                      <p className="text-xl font-bold text-slate-900">
                        {formatCurrency(loan.loanAmount)}
                      </p>
                      <span
                        className={`text-xs font-semibold px-2.5 py-1 rounded-full ${statusConfig[loan.status].badge}`}
                      >
                        {loan.status}
                      </span>
                    </div>
                    {loan.purpose && (
                      <p className="text-sm text-slate-500 mb-2">
                        {loan.purpose}
                      </p>
                    )}
                    <div className="flex items-center gap-4 text-xs text-slate-400">
                      <span>Applied {formatDate(loan.createdAt)}</span>
                      {loan.updatedAt && loan.updatedAt !== loan.createdAt && (
                        <span>· Decision {formatDate(loan.updatedAt)}</span>
                      )}
                    </div>
                    {loan.adminNote && (
                      <p className="mt-2 text-sm text-slate-600 bg-slate-50 rounded-lg px-3 py-2 italic border border-slate-100">
                        &ldquo;{loan.adminNote}&rdquo;
                      </p>
                    )}
                  </div>
                  <RiskBadge level={loan.riskLevel} score={loan.riskScore} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </UserLayout>
  );
}
