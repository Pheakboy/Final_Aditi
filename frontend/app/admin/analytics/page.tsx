"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import { adminApi } from "../../../services/api";
import { AnalyticsData } from "../../../types";

const MONTH_NAMES = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

export default function AdminAnalyticsPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [dataLoading, setDataLoading] = useState(true);
  const [dataError, setDataError] = useState("");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  useEffect(() => {
    if (user && isAdmin) {
      adminApi
        .getAnalytics()
        .then((res) => setAnalytics(res.data.data || null))
        .catch((err) => {
          console.error("Failed to fetch analytics", err);
          setDataError("Failed to load analytics. Please refresh.");
        })
        .finally(() => setDataLoading(false));
    }
  }, [user, isAdmin]);

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-indigo-500 border-t-transparent"></div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-6">
            {dataError}
          </div>
        )}

        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Analytics</h1>
          <p className="text-gray-500 mt-1">
            Loan portfolio risk and performance overview
          </p>
        </div>

        {!analytics ? (
          <div className="bg-white rounded-xl border border-gray-200 p-12 text-center text-gray-500">
            No analytics data available yet.
          </div>
        ) : (
          <div className="space-y-8">
            {/* Risk Distribution */}
            <section>
              <h2 className="text-lg font-semibold text-gray-800 mb-4">
                Risk Distribution
              </h2>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-white rounded-xl border border-gray-200 p-5">
                  <p className="text-xs font-medium text-gray-500 uppercase mb-1">
                    Total Loans
                  </p>
                  <p className="text-3xl font-bold text-gray-900">
                    {analytics.riskDistribution.total}
                  </p>
                </div>
                <div className="bg-green-50 rounded-xl border border-green-200 p-5">
                  <p className="text-xs font-medium text-green-600 uppercase mb-1">
                    Low Risk
                  </p>
                  <p className="text-3xl font-bold text-green-700">
                    {analytics.riskDistribution.low}
                  </p>
                  {analytics.riskDistribution.total > 0 && (
                    <p className="text-xs text-green-500 mt-1">
                      {Math.round(
                        (analytics.riskDistribution.low /
                          analytics.riskDistribution.total) *
                          100,
                      )}
                      %
                    </p>
                  )}
                </div>
                <div className="bg-yellow-50 rounded-xl border border-yellow-200 p-5">
                  <p className="text-xs font-medium text-yellow-600 uppercase mb-1">
                    Medium Risk
                  </p>
                  <p className="text-3xl font-bold text-yellow-700">
                    {analytics.riskDistribution.medium}
                  </p>
                  {analytics.riskDistribution.total > 0 && (
                    <p className="text-xs text-yellow-500 mt-1">
                      {Math.round(
                        (analytics.riskDistribution.medium /
                          analytics.riskDistribution.total) *
                          100,
                      )}
                      %
                    </p>
                  )}
                </div>
                <div className="bg-red-50 rounded-xl border border-red-200 p-5">
                  <p className="text-xs font-medium text-red-600 uppercase mb-1">
                    High Risk
                  </p>
                  <p className="text-3xl font-bold text-red-700">
                    {analytics.riskDistribution.high}
                  </p>
                  {analytics.riskDistribution.total > 0 && (
                    <p className="text-xs text-red-500 mt-1">
                      {Math.round(
                        (analytics.riskDistribution.high /
                          analytics.riskDistribution.total) *
                          100,
                      )}
                      %
                    </p>
                  )}
                </div>
              </div>
            </section>

            {/* Approval Rate */}
            <section>
              <h2 className="text-lg font-semibold text-gray-800 mb-4">
                Approval Rate
              </h2>
              <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
                <div className="bg-green-50 rounded-xl border border-green-200 p-5">
                  <p className="text-xs font-medium text-green-600 uppercase mb-1">
                    Approved
                  </p>
                  <p className="text-3xl font-bold text-green-700">
                    {analytics.approvalRate.approved}
                  </p>
                  <p className="text-sm text-green-600 mt-1 font-medium">
                    {analytics.approvalRate.approvalPercentage.toFixed(1)}%
                  </p>
                </div>
                <div className="bg-red-50 rounded-xl border border-red-200 p-5">
                  <p className="text-xs font-medium text-red-600 uppercase mb-1">
                    Rejected
                  </p>
                  <p className="text-3xl font-bold text-red-700">
                    {analytics.approvalRate.rejected}
                  </p>
                  <p className="text-sm text-red-600 mt-1 font-medium">
                    {analytics.approvalRate.rejectionPercentage.toFixed(1)}%
                  </p>
                </div>
                <div className="bg-yellow-50 rounded-xl border border-yellow-200 p-5">
                  <p className="text-xs font-medium text-yellow-600 uppercase mb-1">
                    Pending
                  </p>
                  <p className="text-3xl font-bold text-yellow-700">
                    {analytics.approvalRate.pending}
                  </p>
                </div>
              </div>
            </section>

            {/* Monthly Stats */}
            <section>
              <h2 className="text-lg font-semibold text-gray-800 mb-4">
                Monthly Applications
              </h2>
              <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                {analytics.monthlyStats.length === 0 ? (
                  <p className="p-6 text-center text-gray-500 text-sm">
                    No monthly data available.
                  </p>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 border-b border-gray-200">
                      <tr>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Year
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Month
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Applications
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {analytics.monthlyStats.map((stat, idx) => (
                        <tr key={idx} className="hover:bg-gray-50">
                          <td className="px-4 py-3 text-gray-700">
                            {stat.year}
                          </td>
                          <td className="px-4 py-3 text-gray-700">
                            {MONTH_NAMES[stat.month - 1] ?? stat.month}
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-3">
                              <span className="font-semibold text-gray-900">
                                {stat.count}
                              </span>
                              <div className="flex-1 bg-gray-100 rounded-full h-2 max-w-30">
                                <div
                                  className="bg-blue-500 h-2 rounded-full"
                                  style={{
                                    width: `${Math.min(
                                      100,
                                      (stat.count /
                                        Math.max(
                                          ...analytics.monthlyStats.map(
                                            (s) => s.count,
                                          ),
                                        )) *
                                        100,
                                    )}%`,
                                  }}
                                />
                              </div>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>

            {/* Top High-Risk Users */}
            <section>
              <h2 className="text-lg font-semibold text-gray-800 mb-4">
                Top High-Risk Users
              </h2>
              <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
                {analytics.topHighRiskUsers.length === 0 ? (
                  <p className="p-6 text-center text-gray-500 text-sm">
                    No high-risk users found.
                  </p>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="bg-gray-50 border-b border-gray-200">
                      <tr>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          #
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          User
                        </th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-gray-500 uppercase">
                          Max Risk Score
                        </th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {analytics.topHighRiskUsers.map((u, idx) => (
                        <tr key={idx} className="hover:bg-gray-50">
                          <td className="px-4 py-3 text-gray-400 font-mono text-xs">
                            {idx + 1}
                          </td>
                          <td className="px-4 py-3">
                            <p className="font-medium text-gray-900">
                              {u.username}
                            </p>
                            <p className="text-xs text-gray-400">{u.email}</p>
                          </td>
                          <td className="px-4 py-3">
                            <span className="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-red-100 text-red-700">
                              {u.riskScore.toFixed(1)}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            </section>
          </div>
        )}
      </main>
    </div>
  );
}
