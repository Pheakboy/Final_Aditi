"use client";

import { useEffect, useState } from "react";
import { useRouter, useParams } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../../context/AuthContext";
import Sidebar from "../../../../components/Sidebar";
import RiskBadge from "../../../../components/RiskBadge";
import { adminApi } from "../../../../services/api";
import { UserProfile } from "../../../../types";
import { formatCurrency, formatDate } from "../../../../utils/format";

export default function AdminUserProfilePage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const params = useParams();
  const userId = params?.id as string;

  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataError, setDataError] = useState("");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  useEffect(() => {
    if (user && isAdmin && userId) {
      adminApi
        .getUserProfile(userId)
        .then((res) => setProfile(res.data.data))
        .catch((err) => {
          console.error("Failed to fetch user profile", err);
          setDataError("Failed to load user profile. Please try again.");
        })
        .finally(() => setDataLoading(false));
    }
  }, [user, isAdmin, userId]);

  if (isLoading || dataLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  const riskColors: Record<string, string> = {
    LOW: "text-green-600 bg-green-50 border-green-200",
    MEDIUM: "text-yellow-600 bg-yellow-50 border-yellow-200",
    HIGH: "text-red-600 bg-red-50 border-red-200",
  };

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        {/* Back */}
        <Link
          href="/admin/users"
          className="inline-flex items-center gap-2 text-sm text-gray-500 hover:text-gray-700 mb-6 transition-colors"
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
              d="M15 19l-7-7 7-7"
            />
          </svg>
          Back to Users
        </Link>

        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-6">
            {dataError}
          </div>
        )}

        {!profile ? (
          <div className="bg-white rounded-xl border border-gray-200 p-12 text-center text-gray-500">
            User not found.
          </div>
        ) : (
          <div className="space-y-6">
            {/* Header */}
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-14 h-14 rounded-full bg-blue-100 flex items-center justify-center text-blue-600 font-bold text-xl">
                    {profile.username.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <h1 className="text-2xl font-bold text-gray-900">
                      {profile.username}
                    </h1>
                    <p className="text-gray-500">{profile.email}</p>
                    <div className="flex items-center gap-2 mt-1">
                      {profile.roles.map((r) => (
                        <span
                          key={r}
                          className="px-2 py-0.5 bg-blue-100 text-blue-700 text-xs font-medium rounded-full"
                        >
                          {r}
                        </span>
                      ))}
                      <span
                        className={`px-2 py-0.5 text-xs font-medium rounded-full ${profile.enabled ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-500"}`}
                      >
                        {profile.enabled ? "Active" : "Disabled"}
                      </span>
                    </div>
                  </div>
                </div>
                {profile.latestRiskLevel && (
                  <div
                    className={`px-4 py-2 rounded-xl border text-sm font-semibold ${riskColors[profile.latestRiskLevel] || "text-gray-600 bg-gray-50 border-gray-200"}`}
                  >
                    {profile.latestRiskLevel} RISK
                    {profile.latestRiskScore != null && (
                      <span className="block text-xs font-normal text-center">
                        Score: {profile.latestRiskScore.toFixed(1)}
                      </span>
                    )}
                  </div>
                )}
              </div>
              {(profile.phoneNumber || profile.address || profile.bio) && (
                <div className="mt-4 pt-4 border-t border-gray-100 grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                  {profile.phoneNumber && (
                    <div>
                      <span className="text-gray-400 text-xs uppercase block mb-0.5">
                        Phone
                      </span>
                      {profile.phoneNumber}
                    </div>
                  )}
                  {profile.address && (
                    <div>
                      <span className="text-gray-400 text-xs uppercase block mb-0.5">
                        Address
                      </span>
                      {profile.address}
                    </div>
                  )}
                  {profile.bio && (
                    <div>
                      <span className="text-gray-400 text-xs uppercase block mb-0.5">
                        Bio
                      </span>
                      {profile.bio}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Financial Summary */}
            <div>
              <h2 className="text-lg font-semibold text-gray-800 mb-3">
                Financial Summary
              </h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                  <p className="text-xs text-gray-500 uppercase mb-1">
                    Total Income
                  </p>
                  <p className="text-xl font-bold text-green-600">
                    {formatCurrency(profile.totalIncome)}
                  </p>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                  <p className="text-xs text-gray-500 uppercase mb-1">
                    Total Expenses
                  </p>
                  <p className="text-xl font-bold text-red-500">
                    {formatCurrency(profile.totalExpenses)}
                  </p>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                  <p className="text-xs text-gray-500 uppercase mb-1">
                    Savings Balance
                  </p>
                  <p
                    className={`text-xl font-bold ${profile.savingsBalance >= 0 ? "text-blue-600" : "text-red-600"}`}
                  >
                    {formatCurrency(profile.savingsBalance)}
                  </p>
                </div>
                <div className="bg-white rounded-xl border border-gray-200 p-4">
                  <p className="text-xs text-gray-500 uppercase mb-1">
                    Total Transactions
                  </p>
                  <p className="text-xl font-bold text-gray-900">
                    {profile.totalTransactions}
                  </p>
                </div>
              </div>
            </div>

            {/* Loan History */}
            <div>
              <h2 className="text-lg font-semibold text-gray-800 mb-3">
                Loan History{" "}
                <span className="text-sm font-normal text-gray-400">
                  ({profile.loans.length})
                </span>
              </h2>
              {profile.loans.length === 0 ? (
                <div className="bg-white rounded-xl border border-gray-200 p-8 text-center text-gray-500">
                  No loan applications yet.
                </div>
              ) : (
                <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 border-b border-gray-200">
                      <tr>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Amount
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Purpose
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Risk
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Status
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Applied
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Admin Note
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {profile.loans.map((loan) => {
                        const statusColors: Record<string, string> = {
                          PENDING: "bg-yellow-100 text-yellow-700",
                          APPROVED: "bg-green-100 text-green-700",
                          REJECTED: "bg-red-100 text-red-700",
                        };
                        return (
                          <tr key={loan.id} className="hover:bg-gray-50">
                            <td className="px-4 py-3 font-medium text-gray-900">
                              {formatCurrency(loan.loanAmount)}
                            </td>
                            <td className="px-4 py-3 text-gray-600 max-w-40 truncate">
                              {loan.purpose || "—"}
                            </td>
                            <td className="px-4 py-3">
                              <RiskBadge
                                level={loan.riskLevel}
                                score={loan.riskScore}
                              />
                            </td>
                            <td className="px-4 py-3">
                              <span
                                className={`px-2 py-1 rounded-full text-xs font-medium ${statusColors[loan.status]}`}
                              >
                                {loan.status}
                              </span>
                            </td>
                            <td className="px-4 py-3 text-gray-500 text-xs">
                              {formatDate(loan.createdAt)}
                            </td>
                            <td className="px-4 py-3 text-gray-500 max-w-50 truncate text-xs">
                              {loan.adminNote || "—"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Recent Transactions */}
            <div>
              <h2 className="text-lg font-semibold text-gray-800 mb-3">
                Recent Transactions{" "}
                <span className="text-sm font-normal text-gray-400">
                  (last 10)
                </span>
              </h2>
              {profile.recentTransactions.length === 0 ? (
                <div className="bg-white rounded-xl border border-gray-200 p-8 text-center text-gray-500">
                  No transactions yet.
                </div>
              ) : (
                <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 border-b border-gray-200">
                      <tr>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Type
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Amount
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Description
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Date
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {profile.recentTransactions.map((tx) => (
                        <tr key={tx.id} className="hover:bg-gray-50">
                          <td className="px-4 py-3">
                            <span
                              className={`px-2 py-1 rounded-full text-xs font-medium ${tx.type === "INCOME" ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}
                            >
                              {tx.type}
                            </span>
                          </td>
                          <td
                            className={`px-4 py-3 font-medium ${tx.type === "INCOME" ? "text-green-600" : "text-red-500"}`}
                          >
                            {tx.type === "INCOME" ? "+" : "-"}
                            {formatCurrency(tx.amount)}
                          </td>
                          <td className="px-4 py-3 text-gray-600">
                            {tx.description || "—"}
                          </td>
                          <td className="px-4 py-3 text-gray-500 text-xs">
                            {formatDate(tx.transactionDate || tx.createdAt)}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
