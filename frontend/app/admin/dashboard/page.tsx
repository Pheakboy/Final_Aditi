"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import { adminApi } from "../../../services/api";
import AdminLayout from "../../../components/admin/AdminLayout";
import { Loan, AnalyticsData } from "../../../types";
import LoadingScreen from "../../../components/ui/LoadingScreen";
import ErrorAlert from "../../../components/ui/ErrorAlert";
import StatCard from "../../../components/ui/StatCard";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
} from "chart.js";
import { Doughnut, Line } from "react-chartjs-2";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Filler,
);

export default function AdminDashboardPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [allLoans, setAllLoans] = useState<Loan[]>([]);
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchData = async () => {
    setDataLoading(true);
    try {
      const [allRes, analyticsRes] = await Promise.all([
        adminApi.getAllLoans(),
        adminApi.getAnalytics(),
      ]);
      setAllLoans(allRes.data.data || []);
      setAnalytics(analyticsRes.data.data || null);
    } catch {
      setDataError("Failed to load dashboard data. Please refresh.");
    } finally {
      setDataLoading(false);
    }
  };

  useEffect(() => {
    if (user && isAdmin) {
      fetchData();
    }
  }, [user, isAdmin]);

  if (isLoading) {
    return <LoadingScreen color="border-indigo-500" />;
  }

  const approvedCount = allLoans.filter((l) => l.status === "APPROVED").length;
  const rejectedCount = allLoans.filter((l) => l.status === "REJECTED").length;
  const pendingCount = allLoans.filter((l) => l.status === "PENDING").length;

  // ── Chart data ────────────────────────────────────────────────────────────
  const loanStatusChartData = {
    labels: ["Approved", "Rejected", "Pending"],
    datasets: [
      {
        data: [approvedCount, rejectedCount, pendingCount],
        backgroundColor: ["#10b981", "#ef4444", "#f59e0b"],
        borderColor: ["#d1fae5", "#fee2e2", "#fef3c7"],
        borderWidth: 3,
        hoverOffset: 6,
      },
    ],
  };

  const riskChartData = analytics
    ? {
        labels: ["Low Risk", "Medium Risk", "High Risk"],
        datasets: [
          {
            data: [
              analytics.riskDistribution.low,
              analytics.riskDistribution.medium,
              analytics.riskDistribution.high,
            ],
            backgroundColor: ["#10b981", "#f59e0b", "#ef4444"],
            borderColor: ["#d1fae5", "#fef3c7", "#fee2e2"],
            borderWidth: 3,
            hoverOffset: 6,
          },
        ],
      }
    : null;

  const sortedMonthly = analytics
    ? [...analytics.monthlyStats].sort((a, b) =>
        a.year !== b.year ? a.year - b.year : a.month - b.month,
      )
    : [];

  const monthlyChartData = {
    labels: sortedMonthly.map((m) =>
      new Date(m.year, m.month - 1).toLocaleString("en-US", {
        month: "short",
        year: "2-digit",
      }),
    ),
    datasets: [
      {
        label: "Applications",
        data: sortedMonthly.map((m) => m.count),
        borderColor: "#6366f1",
        backgroundColor: (ctx: { chart: ChartJS }) => {
          const gradient = ctx.chart.ctx.createLinearGradient(0, 0, 0, 280);
          gradient.addColorStop(0, "rgba(99, 102, 241, 0.3)");
          gradient.addColorStop(1, "rgba(99, 102, 241, 0.0)");
          return gradient;
        },
        pointBackgroundColor: "#ffffff",
        pointBorderColor: "#6366f1",
        pointBorderWidth: 2.5,
        pointRadius: 5,
        pointHoverRadius: 8,
        pointHoverBackgroundColor: "#6366f1",
        pointHoverBorderColor: "#ffffff",
        pointHoverBorderWidth: 2,
        borderWidth: 2.5,
        fill: true,
        tension: 0.45,
      },
    ],
  };

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        position: "bottom" as const,
        labels: { padding: 16, font: { size: 12 } },
      },
      tooltip: {
        callbacks: {
          label: (ctx: {
            label: string;
            raw: unknown;
            chart: { data: { datasets: Array<{ data: unknown[] }> } };
          }) =>
            ` ${ctx.label}: ${ctx.raw} (${Math.round(((ctx.raw as number) / (ctx.chart.data.datasets[0].data as number[]).reduce((a, b) => a + b, 0)) * 100)}%)`,
        },
      },
    },
    cutout: "65%",
  };

  const lineOptions = {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index" as const, intersect: false },
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: "#1e293b",
        titleColor: "#94a3b8",
        bodyColor: "#f1f5f9",
        padding: 12,
        cornerRadius: 10,
        callbacks: {
          label: (ctx: { parsed: { y: number | null } }) =>
            `  ${ctx.parsed.y ?? 0} application${(ctx.parsed.y ?? 0) !== 1 ? "s" : ""}`,
        },
      },
    },
    scales: {
      y: {
        beginAtZero: true,
        ticks: { stepSize: 1, color: "#94a3b8", font: { size: 11 } },
        grid: { color: "rgba(0,0,0,0.05)" },
        border: { display: false },
      },
      x: {
        ticks: { color: "#94a3b8", font: { size: 11 } },
        grid: { display: false },
        border: { display: false },
      },
    },
  };

  return (
    <AdminLayout title="Admin Dashboard" onRefresh={fetchData}>
      <div className="p-6 lg:p-10">
        {dataError && <ErrorAlert message={dataError} />}

        {/* Stat Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-10">
          <StatCard
            label="Total Applications"
            value={allLoans.length}
            iconBg="gradient-indigo"
            icon={
              <svg
                className="w-7 h-7 text-blue-500"
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
            }
          />
          <StatCard
            label="Pending Review"
            value={pendingCount}
            valueColor="text-amber-600"
            iconBg="gradient-amber"
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
                  d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            }
          />
          <StatCard
            label="Approved"
            value={approvedCount}
            valueColor="text-emerald-600"
            iconBg="gradient-emerald"
            icon={
              <svg
                className="w-7 h-7 text-green-500"
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
          />
          <StatCard
            label="Rejected"
            value={rejectedCount}
            valueColor="text-red-500"
            iconBg="gradient-rose"
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
                  d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            }
          />
        </div>

        {/* Charts */}
        {dataLoading ? (
          <div className="flex items-center justify-center h-64 text-slate-400 text-sm font-medium">
            Loading charts…
          </div>
        ) : (
          <div
            className="space-y-6 animate-slide-up"
            style={{ animationDelay: "100ms" }}
          >
            {/* Row 1 — two doughnuts */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Loan Status */}
              <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6">
                <h2 className="text-base font-bold text-slate-800 mb-1">
                  Loan Status Distribution
                </h2>
                <p className="text-xs text-slate-400 mb-5">
                  Breakdown of all {allLoans.length} applications
                </p>
                <div className="relative h-60">
                  <Doughnut
                    data={loanStatusChartData}
                    options={doughnutOptions}
                  />
                </div>
                <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                  {[
                    {
                      label: "Approved",
                      value: approvedCount,
                      color: "text-emerald-600 bg-emerald-50",
                    },
                    {
                      label: "Rejected",
                      value: rejectedCount,
                      color: "text-red-500 bg-red-50",
                    },
                    {
                      label: "Pending",
                      value: pendingCount,
                      color: "text-amber-600 bg-amber-50",
                    },
                  ].map(({ label, value, color }) => (
                    <div
                      key={label}
                      className={`rounded-xl px-3 py-2 ${color}`}
                    >
                      <p className="text-lg font-black">{value}</p>
                      <p className="text-[11px] font-semibold opacity-80">
                        {label}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Risk Distribution */}
              <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6">
                <h2 className="text-base font-bold text-slate-800 mb-1">
                  Risk Distribution
                </h2>
                <p className="text-xs text-slate-400 mb-5">
                  Based on {analytics?.riskDistribution.total ?? 0} scored
                  applications
                </p>
                <div className="relative h-60">
                  {riskChartData ? (
                    <Doughnut data={riskChartData} options={doughnutOptions} />
                  ) : (
                    <div className="flex items-center justify-center h-full text-slate-400 text-sm">
                      No data yet
                    </div>
                  )}
                </div>
                {analytics && (
                  <div className="mt-4 grid grid-cols-3 gap-2 text-center">
                    {[
                      {
                        label: "Low",
                        value: analytics.riskDistribution.low,
                        color: "text-emerald-600 bg-emerald-50",
                      },
                      {
                        label: "Medium",
                        value: analytics.riskDistribution.medium,
                        color: "text-amber-600 bg-amber-50",
                      },
                      {
                        label: "High",
                        value: analytics.riskDistribution.high,
                        color: "text-red-500 bg-red-50",
                      },
                    ].map(({ label, value, color }) => (
                      <div
                        key={label}
                        className={`rounded-xl px-3 py-2 ${color}`}
                      >
                        <p className="text-lg font-black">{value}</p>
                        <p className="text-[11px] font-semibold opacity-80">
                          {label} Risk
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Row 2 — monthly trend */}
            <div className="bg-white rounded-2xl border border-slate-200 shadow-sm p-6">
              <div className="flex items-start justify-between mb-5">
                <div>
                  <h2 className="text-base font-bold text-slate-800 mb-1">
                    Monthly Applications Trend
                  </h2>
                  <p className="text-xs text-slate-400">
                    Number of loan applications submitted per month
                  </p>
                </div>
                {sortedMonthly.length > 0 && (
                  <div className="text-right">
                    <p className="text-2xl font-black text-indigo-600">
                      {sortedMonthly.reduce((s, m) => s + m.count, 0)}
                    </p>
                    <p className="text-[11px] text-slate-400 font-medium">
                      total
                    </p>
                  </div>
                )}
              </div>
              <div className="relative h-72">
                {sortedMonthly.length > 0 ? (
                  <Line data={monthlyChartData} options={lineOptions} />
                ) : (
                  <div className="flex items-center justify-center h-full text-slate-400 text-sm">
                    No monthly data yet
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </div>
    </AdminLayout>
  );
}
