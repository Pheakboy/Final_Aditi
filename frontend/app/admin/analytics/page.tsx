"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
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
        .catch((err) => {
          console.error("Failed to fetch analytics", err);
          setDataError("Failed to load analytics. Please refresh.");
        })
        .finally(() => setDataLoading(false));
    }
  }, [user, isAdmin]);

  if (isLoading) {
    return <LoadingScreen color="border-indigo-500" />;
  }

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        {dataError && <ErrorAlert message={dataError} />}

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
            <RiskDistributionSection
              riskDistribution={analytics.riskDistribution}
            />
            <ApprovalRateSection approvalRate={analytics.approvalRate} />
            <MonthlyStatsTable monthlyStats={analytics.monthlyStats} />
            <TopHighRiskTable topHighRiskUsers={analytics.topHighRiskUsers} />
          </div>
        )}
      </main>
    </div>
  );
}
