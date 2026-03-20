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

export default function LoanHistoryPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [loans, setLoans] = useState<Loan[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [filter, setFilter] = useState<
    "ALL" | "PENDING" | "APPROVED" | "ACTIVE" | "REJECTED" | "COMPLETED"
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
          setDataError("Failed to load loan history. Please refresh."),
        )
        .finally(() => setDataLoading(false));
    }
  }, [user]);

  const filteredLoans =
    filter === "ALL" ? loans : loans.filter((l) => l.status === filter);

  const riskColor = (level?: string) => {
    if (level === "LOW") return "text-emerald-600 bg-emerald-50";
    if (level === "MEDIUM") return "text-amber-600 bg-amber-50";
    return "text-red-600 bg-red-50";
  };

  if (isLoading)
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent" />
      </div>
    );

  return (
    <UserLayout
      title="Loan History"
      subtitle="All your loan applications and their outcomes"
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

        {/* Filter Tabs */}
        {dataLoading ? (
          <div className="flex gap-2 mb-6 animate-pulse">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="h-9 bg-slate-200 rounded-xl w-24"></div>
            ))}
          </div>
        ) : (
          <div className="flex gap-2 mb-6">
            {(
              [
                "ALL",
                "PENDING",
                "APPROVED",
                "ACTIVE",
                "REJECTED",
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
        )}

        {/* Loans Table */}
        {dataLoading ? (
          <div className="bg-white rounded-2xl card-shadow overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-100">
                <tr>
                  {[
                    "Amount",
                    "Purpose",
                    "Risk Score",
                    "Status",
                    "Applied Date",
                    "Decision Date",
                    "Note",
                  ].map((h) => (
                    <th
                      key={h}
                      className="text-left px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {Array.from({ length: 6 }).map((_, i) => (
                  <tr key={i} className="animate-pulse">
                    <td className="px-5 py-3">
                      <div className="h-4 bg-slate-200 rounded w-20"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-3 bg-slate-200 rounded w-28"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-5 bg-slate-200 rounded-full w-16"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-5 bg-slate-200 rounded-full w-16"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-3 bg-slate-200 rounded w-24"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-3 bg-slate-200 rounded w-24"></div>
                    </td>
                    <td className="px-5 py-3">
                      <div className="h-3 bg-slate-200 rounded w-20"></div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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
                  d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
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
          <div className="bg-white rounded-2xl card-shadow overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-50 border-b border-slate-100">
                <tr>
                  {[
                    "Amount",
                    "Purpose",
                    "Risk Score",
                    "Status",
                    "Applied Date",
                    "Decision Date",
                    "Note",
                  ].map((h) => (
                    <th
                      key={h}
                      className="text-left px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide"
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-50">
                {filteredLoans.map((loan) => (
                  <tr
                    key={loan.id}
                    className="hover:bg-slate-50 transition-colors"
                  >
                    <td className="px-5 py-3 font-semibold text-slate-900">
                      {formatCurrency(loan.loanAmount)}
                    </td>
                    <td className="px-5 py-3 text-slate-500 max-w-32 truncate">
                      {loan.purpose || "—"}
                    </td>
                    <td className="px-5 py-3">
                      <RiskBadge
                        level={loan.riskLevel}
                        score={loan.riskScore}
                      />
                    </td>
                    <td className="px-5 py-3">
                      <span
                        className={`text-xs font-semibold px-2.5 py-1 rounded-full ${
                          loan.status === "APPROVED" || loan.status === "ACTIVE"
                            ? "bg-emerald-100 text-emerald-700"
                            : loan.status === "COMPLETED"
                              ? "bg-blue-100 text-blue-700"
                              : loan.status === "REJECTED"
                                ? "bg-red-100 text-red-700"
                                : "bg-amber-100 text-amber-700"
                        }`}
                      >
                        {loan.status}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-slate-400 text-xs whitespace-nowrap">
                      {formatDate(loan.createdAt)}
                    </td>
                    <td className="px-5 py-3 text-slate-400 text-xs whitespace-nowrap">
                      {loan.updatedAt && loan.updatedAt !== loan.createdAt
                        ? formatDate(loan.updatedAt)
                        : "—"}
                    </td>
                    <td className="px-5 py-3 text-slate-500 text-xs max-w-40 truncate italic">
                      {loan.adminNote || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </UserLayout>
  );
}
