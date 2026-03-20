"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import AdminLayout from "../../../components/admin/AdminLayout";
import { adminApi } from "../../../services/api";
import { AnalyticsData } from "../../../types";
import LoadingScreen from "../../../components/ui/LoadingScreen";
import ErrorAlert from "../../../components/ui/ErrorAlert";
import RiskDistributionSection from "../../../components/admin/analytics/RiskDistributionSection";
import ApprovalRateSection from "../../../components/admin/analytics/ApprovalRateSection";
import MonthlyStatsTable from "../../../components/admin/analytics/MonthlyStatsTable";
import TopHighRiskTable from "../../../components/admin/analytics/TopHighRiskTable";

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
        .catch(() => {
          setDataError("Failed to load analytics. Please refresh.");
        })
        .finally(() => setDataLoading(false));
    }
  }, [user, isAdmin]);

  if (isLoading) {
    return <LoadingScreen color="border-indigo-500" />;
  }

  return (
    <AdminLayout
      title="Analytics"
      subtitle="Loan portfolio risk and performance overview"
    >
      <div className="p-8">
        {dataError && <ErrorAlert message={dataError} />}

        {dataLoading ? (
          <div className="space-y-6 animate-pulse">
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
              {Array.from({ length: 4 }).map((_, i) => (
                <div
                  key={i}
                  className="bg-white rounded-xl border border-gray-200 p-5"
                >
                  <div className="h-3 bg-gray-200 rounded w-24 mb-3"></div>
                  <div className="h-8 bg-gray-200 rounded w-20"></div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {Array.from({ length: 2 }).map((_, i) => (
                <div
                  key={i}
                  className="bg-white rounded-xl border border-gray-200 p-6"
                >
                  <div className="h-4 bg-gray-200 rounded w-40 mb-2"></div>
                  <div className="h-64 bg-gray-100 rounded-xl mt-4"></div>
                </div>
              ))}
            </div>
            <div className="bg-white rounded-xl border border-gray-200 p-6">
              <div className="h-4 bg-gray-200 rounded w-36 mb-4"></div>
              {Array.from({ length: 5 }).map((_, i) => (
                <div
                  key={i}
                  className="flex gap-4 py-3 border-t border-gray-100"
                >
                  <div className="h-3 bg-gray-200 rounded w-20"></div>
                  <div className="h-3 bg-gray-200 rounded w-16"></div>
                  <div className="h-3 bg-gray-200 rounded flex-1"></div>
                </div>
              ))}
            </div>
          </div>
        ) : !analytics ? (
          <div className="bg-white rounded-xl border border-gray-200 p-12 text-center text-gray-500">
            No analytics data available yet.
          </div>
        ) : (
          <div className="space-y-8">
            <RiskDistributionSection
              riskDistribution={analytics.riskDistribution}
            />
            <ApprovalRateSection approvalRate={analytics.approvalRate} />
            <MonthlyStatsTable monthlyStats={analytics.monthlyStats} />
            <TopHighRiskTable topHighRiskUsers={analytics.topHighRiskUsers} />
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
