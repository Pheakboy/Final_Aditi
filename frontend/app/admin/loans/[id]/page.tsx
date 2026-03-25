"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "../../../../context/AuthContext";
import AdminLayout from "../../../../components/admin/AdminLayout";
import RiskBadge from "../../../../components/RiskBadge";
import { adminApi } from "../../../../services/api";
import { Loan } from "../../../../types";
import { formatCurrency, formatDate } from "../../../../utils/format";
import LoadingScreen from "../../../../components/ui/LoadingScreen";
import axios from "axios";

export default function AdminLoanDetailPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const params = useParams();
  const loanId = params.id as string;

  const [loan, setLoan] = useState<Loan | null>(null);
  const [dataLoading, setDataLoading] = useState(true);
  const [note, setNote] = useState("");
  const [processing, setProcessing] = useState(false);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  useEffect(() => {
    if (user && isAdmin && loanId) {
      adminApi
        .getLoanById(loanId)
        .then((res) => setLoan(res.data.data))
        .catch(() => setError("Failed to load loan details."))
        .finally(() => setDataLoading(false));
    }
  }, [user, isAdmin, loanId]);

  const handleDecide = async (decision: "APPROVED" | "REJECTED") => {
    setProcessing(true);
    setError("");
    setSuccess("");
    try {
      await adminApi.decideLoan(loanId, { decision, note: note || undefined });
      setSuccess(`Loan ${decision.toLowerCase()} successfully.`);
      setNote("");
      const res = await adminApi.getLoanById(loanId);
      setLoan(res.data.data);
    } catch (err: unknown) {
      setError(
        axios.isAxiosError(err)
          ? (err.response?.data?.message ?? "Action failed")
          : "Action failed",
      );
    } finally {
      setProcessing(false);
    }
  };

  const statusConfig: Record<string, { badge: string; label: string }> = {
    PENDING: {
      badge: "bg-amber-50 text-amber-700 border border-amber-200",
      label: "Pending",
    },
    APPROVED: {
      badge: "bg-emerald-50 text-emerald-700 border border-emerald-200",
      label: "Approved",
    },
    ACTIVE: {
      badge: "bg-teal-50 text-teal-700 border border-teal-200",
      label: "Active",
    },
    REJECTED: {
      badge: "bg-red-50 text-red-700 border border-red-200",
      label: "Rejected",
    },
    COMPLETED: {
      badge: "bg-blue-50 text-blue-700 border border-blue-200",
      label: "Completed",
    },
  };

  if (isLoading) return <LoadingScreen color="border-indigo-500" />;

  const net = loan ? loan.monthlyIncome - loan.monthlyExpense : 0;

  return (
    <AdminLayout title="Loan Detail" subtitle="Full loan application review">
      <div className="p-6 lg:p-8">
        {/* â”€â”€ Skeleton â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        {dataLoading ? (
          <div className="animate-pulse">
            <div className="h-4 w-36 bg-slate-200 rounded-full mb-5" />
            <div className="rounded-2xl bg-slate-200 h-28 w-full mb-6" />
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 space-y-5">
                <div className="bg-white rounded-2xl border border-slate-200 p-6">
                  <div className="h-3 w-20 bg-slate-200 rounded-full mb-4" />
                  <div className="flex items-center gap-4">
                    <div className="w-14 h-14 rounded-2xl bg-slate-200 shrink-0" />
                    <div className="flex-1 space-y-2">
                      <div className="h-4 w-36 bg-slate-200 rounded-full" />
                      <div className="h-3 w-48 bg-slate-100 rounded-full" />
                    </div>
                  </div>
                </div>
                <div className="bg-white rounded-2xl border border-slate-200 p-6">
                  <div className="h-3 w-40 bg-slate-200 rounded-full mb-4" />
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    {[...Array(4)].map((_, i) => (
                      <div key={i} className="rounded-xl bg-slate-100 h-20" />
                    ))}
                  </div>
                  <div className="grid grid-cols-2 gap-3 mt-3">
                    <div className="rounded-xl bg-slate-100 h-14" />
                    <div className="rounded-xl bg-slate-100 h-14" />
                  </div>
                </div>
              </div>
              <div className="space-y-5">
                <div className="bg-white rounded-2xl border border-slate-200 h-48" />
                <div className="bg-white rounded-2xl border border-slate-200 h-52" />
              </div>
            </div>
          </div>
        ) : (
          <>
            {/* â”€â”€ Back button â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
            <button
              onClick={() => router.back()}
              className="flex items-center gap-1.5 text-slate-500 hover:text-slate-700 text-sm mb-5 transition-colors group"
            >
              <svg
                className="w-4 h-4 group-hover:-translate-x-0.5 transition-transform"
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
              Back to Applicants
            </button>

            {/* â”€â”€ Hero banner â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
            {loan && (
              <div className="relative rounded-2xl overflow-hidden mb-6 gradient-indigo animate-fade-in">
                <div
                  className="absolute inset-0 opacity-20"
                  style={{
                    backgroundImage:
                      "radial-gradient(circle at 80% 50%, white 0%, transparent 60%)",
                  }}
                />
                <div className="relative px-6 py-6 flex flex-col sm:flex-row sm:items-center gap-4 justify-between">
                  <div>
                    <p className="text-indigo-200 text-xs font-semibold uppercase tracking-widest mb-1">
                      Loan Application
                    </p>
                    <h1 className="text-white text-3xl font-extrabold tracking-tight">
                      {formatCurrency(loan.loanAmount)}
                    </h1>
                    <p className="text-indigo-200 text-sm mt-1">
                      Applied {formatDate(loan.createdAt)}
                    </p>
                  </div>
                  <div className="flex flex-col items-start sm:items-end gap-2">
                    <span
                      className={`text-xs font-bold px-3 py-1.5 rounded-full ${statusConfig[loan.status]?.badge ?? ""}`}
                    >
                      {statusConfig[loan.status]?.label ?? loan.status}
                    </span>
                    {loan.riskLevel && (
                      <RiskBadge
                        level={loan.riskLevel}
                        score={loan.riskScore}
                      />
                    )}
                  </div>
                </div>
              </div>
            )}

            {/* â”€â”€ Alerts â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-5 flex items-center gap-2">
                <svg
                  className="w-4 h-4 shrink-0"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                  />
                </svg>
                {error}
              </div>
            )}
            {success && (
              <div className="bg-emerald-50 border border-emerald-200 text-emerald-700 px-4 py-3 rounded-xl text-sm mb-5 flex items-center gap-2">
                <svg
                  className="w-4 h-4 shrink-0"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M5 13l4 4L19 7"
                  />
                </svg>
                {success}
              </div>
            )}

            {/* â”€â”€ Main content grid â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
            {loan && (
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 animate-slide-up">
                {/* â”€â”€ LEFT (2/3) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
                <div className="lg:col-span-2 space-y-5">
                  {/* Applicant card */}
                  <div className="bg-white rounded-2xl border border-slate-200 card-shadow p-6">
                    <p className="text-[11px] font-bold text-slate-400 uppercase tracking-widest mb-4">
                      Applicant
                    </p>
                    <div className="flex items-center gap-4">
                      <div className="w-14 h-14 rounded-2xl gradient-indigo flex items-center justify-center text-white font-extrabold text-xl shrink-0 shadow-md">
                        {loan.applicantUsername?.charAt(0).toUpperCase() ?? "?"}
                      </div>
                      <div>
                        <p className="font-bold text-slate-800 text-lg leading-tight">
                          {loan.applicantUsername || "â€”"}
                        </p>
                        <p className="text-slate-500 text-sm mt-0.5">
                          {loan.applicantEmail || "â€”"}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Financial snapshot */}
                  <div className="bg-white rounded-2xl border border-slate-200 card-shadow p-6">
                    <p className="text-[11px] font-bold text-slate-400 uppercase tracking-widest mb-4">
                      Financial Snapshot
                    </p>
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                      <div className="rounded-xl p-4 bg-indigo-50 border border-indigo-100">
                        <p className="text-[10px] font-bold text-indigo-400 uppercase tracking-widest mb-1.5">
                          Requested
                        </p>
                        <p className="text-base font-extrabold text-indigo-700">
                          {formatCurrency(loan.loanAmount)}
                        </p>
                      </div>
                      <div className="rounded-xl p-4 bg-emerald-50 border border-emerald-100">
                        <p className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest mb-1.5">
                          Income
                        </p>
                        <p className="text-base font-extrabold text-emerald-700">
                          {formatCurrency(loan.monthlyIncome)}
                        </p>
                      </div>
                      <div className="rounded-xl p-4 bg-rose-50 border border-rose-100">
                        <p className="text-[10px] font-bold text-rose-400 uppercase tracking-widest mb-1.5">
                          Expenses
                        </p>
                        <p className="text-base font-extrabold text-rose-700">
                          {formatCurrency(loan.monthlyExpense)}
                        </p>
                      </div>
                      <div
                        className={`rounded-xl p-4 border ${net >= 0 ? "bg-teal-50 border-teal-100" : "bg-red-50 border-red-100"}`}
                      >
                        <p
                          className={`text-[10px] font-bold uppercase tracking-widest mb-1.5 ${net >= 0 ? "text-teal-400" : "text-red-400"}`}
                        >
                          Net / mo
                        </p>
                        <p
                          className={`text-base font-extrabold ${net >= 0 ? "text-teal-700" : "text-red-700"}`}
                        >
                          {formatCurrency(net)}
                        </p>
                      </div>
                    </div>

                    {/* Dates row */}
                    <div className="grid grid-cols-2 gap-3 mt-3">
                      <div className="rounded-xl p-3.5 bg-slate-50 border border-slate-100">
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">
                          Applied
                        </p>
                        <p className="text-sm font-semibold text-slate-700">
                          {formatDate(loan.createdAt)}
                        </p>
                      </div>
                      <div className="rounded-xl p-3.5 bg-slate-50 border border-slate-100">
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">
                          Last Updated
                        </p>
                        <p className="text-sm font-semibold text-slate-700">
                          {formatDate(loan.updatedAt)}
                        </p>
                      </div>
                    </div>

                    {loan.purpose && (
                      <div className="mt-3 rounded-xl p-3.5 bg-slate-50 border border-slate-100">
                        <p className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">
                          Purpose
                        </p>
                        <p className="text-sm text-slate-700">{loan.purpose}</p>
                      </div>
                    )}
                  </div>

                  {/* Admin note (post-decision) */}
                  {loan.adminNote && (
                    <div className="bg-amber-50 border border-amber-200 rounded-2xl p-5 flex gap-3">
                      <div className="w-8 h-8 rounded-full bg-amber-100 flex items-center justify-center shrink-0 mt-0.5">
                        <svg
                          className="w-4 h-4 text-amber-500"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z"
                          />
                        </svg>
                      </div>
                      <div>
                        <p className="text-xs font-bold text-amber-700 uppercase tracking-wider mb-1">
                          Admin Note
                        </p>
                        <p className="text-sm text-amber-900 italic">
                          &ldquo;{loan.adminNote}&rdquo;
                        </p>
                      </div>
                    </div>
                  )}
                </div>

                {/* â”€â”€ RIGHT (1/3) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
                <div className="space-y-5">
                  {/* Risk assessment card */}
                  <div className="bg-white rounded-2xl border border-slate-200 card-shadow overflow-hidden">
                    <div
                      className={`px-5 py-3 text-xs font-bold uppercase tracking-widest ${loan.riskLevel === "LOW" ? "bg-emerald-500 text-emerald-50" : loan.riskLevel === "MEDIUM" ? "bg-amber-400 text-amber-900" : "bg-rose-500 text-rose-50"}`}
                    >
                      {loan.riskLevel === "LOW"
                        ? "âœ“ Low Risk"
                        : loan.riskLevel === "MEDIUM"
                          ? "âš  Medium Risk"
                          : "âœ• High Risk"}
                    </div>
                    <div className="p-5">
                      {loan.riskScore !== undefined && (
                        <>
                          <div className="flex justify-between text-sm mb-2">
                            <span className="text-slate-500 font-medium">
                              Risk Score
                            </span>
                            <span className="font-bold text-slate-800">
                              {loan.riskScore?.toFixed(1)}{" "}
                              <span className="text-slate-400 font-normal">
                                / 100
                              </span>
                            </span>
                          </div>
                          <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all ${loan.riskLevel === "LOW" ? "bg-emerald-500" : loan.riskLevel === "MEDIUM" ? "bg-amber-400" : "bg-rose-500"}`}
                              style={{
                                width: `${Math.min(100, loan.riskScore ?? 0)}%`,
                              }}
                            />
                          </div>
                          <div className="flex justify-between text-[10px] text-slate-400 mt-1.5 font-medium">
                            <span>Low (0)</span>
                            <span>High (100)</span>
                          </div>
                        </>
                      )}
                      <div className="mt-4 grid grid-cols-3 text-center divide-x divide-slate-100 border border-slate-100 rounded-xl overflow-hidden">
                        {(["LOW", "MEDIUM", "HIGH"] as const).map((lvl) => (
                          <div
                            key={lvl}
                            className={`py-2.5 text-xs font-bold ${loan.riskLevel === lvl ? (lvl === "LOW" ? "bg-emerald-50 text-emerald-700" : lvl === "MEDIUM" ? "bg-amber-50 text-amber-700" : "bg-rose-50 text-rose-700") : "text-slate-400"}`}
                          >
                            {lvl}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Decision card (PENDING only) */}
                  {loan.status === "PENDING" && (
                    <div className="bg-white rounded-2xl border border-slate-200 card-shadow p-5">
                      <p className="text-[11px] font-bold text-slate-400 uppercase tracking-widest mb-4">
                        Make Decision
                      </p>
                      <div className="mb-4">
                        <label className="block text-xs font-semibold text-slate-600 mb-1.5">
                          Note for applicant{" "}
                          <span className="text-slate-400 font-normal">
                            (optional)
                          </span>
                        </label>
                        <textarea
                          value={note}
                          onChange={(e) => setNote(e.target.value)}
                          rows={3}
                          className="w-full px-3 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-700 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent resize-none"
                          placeholder="e.g. Congratulations! / Insufficient incomeâ€¦"
                        />
                      </div>
                      <div className="flex flex-col gap-2.5">
                        <button
                          onClick={() => handleDecide("APPROVED")}
                          disabled={processing}
                          className="w-full flex items-center justify-center gap-2 py-2.5 gradient-emerald text-white text-sm font-bold rounded-xl disabled:opacity-50 transition-all hover:opacity-90 shadow-sm"
                        >
                          {processing ? (
                            <svg
                              className="animate-spin h-4 w-4"
                              fill="none"
                              viewBox="0 0 24 24"
                            >
                              <circle
                                className="opacity-25"
                                cx="12"
                                cy="12"
                                r="10"
                                stroke="currentColor"
                                strokeWidth="4"
                              />
                              <path
                                className="opacity-75"
                                fill="currentColor"
                                d="M4 12a8 8 0 018-8v8H4z"
                              />
                            </svg>
                          ) : (
                            <svg
                              className="w-4 h-4"
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2.5}
                                d="M5 13l4 4L19 7"
                              />
                            </svg>
                          )}
                          {processing ? "Processingâ€¦" : "Approve Loan"}
                        </button>
                        <button
                          onClick={() => handleDecide("REJECTED")}
                          disabled={processing}
                          className="w-full flex items-center justify-center gap-2 py-2.5 gradient-rose text-white text-sm font-bold rounded-xl disabled:opacity-50 transition-all hover:opacity-90 shadow-sm"
                        >
                          {processing ? (
                            <svg
                              className="animate-spin h-4 w-4"
                              fill="none"
                              viewBox="0 0 24 24"
                            >
                              <circle
                                className="opacity-25"
                                cx="12"
                                cy="12"
                                r="10"
                                stroke="currentColor"
                                strokeWidth="4"
                              />
                              <path
                                className="opacity-75"
                                fill="currentColor"
                                d="M4 12a8 8 0 018-8v8H4z"
                              />
                            </svg>
                          ) : (
                            <svg
                              className="w-4 h-4"
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2.5}
                                d="M6 18L18 6M6 6l12 12"
                              />
                            </svg>
                          )}
                          {processing ? "Processingâ€¦" : "Reject Loan"}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Already decided notice */}
                  {loan.status !== "PENDING" && (
                    <div
                      className={`rounded-2xl overflow-hidden border card-shadow ${loan.status === "APPROVED" || loan.status === "ACTIVE" ? "border-emerald-200" : loan.status === "REJECTED" ? "border-red-200" : "border-blue-200"}`}
                    >
                      <div
                        className={`px-5 py-2.5 text-xs font-bold uppercase tracking-widest ${loan.status === "APPROVED" || loan.status === "ACTIVE" ? "gradient-emerald text-white" : loan.status === "REJECTED" ? "gradient-rose text-white" : "bg-blue-500 text-white"}`}
                      >
                        {loan.status === "APPROVED" || loan.status === "ACTIVE"
                          ? "âœ“ Approved"
                          : loan.status === "REJECTED"
                            ? "âœ• Rejected"
                            : loan.status}
                      </div>
                      <div className="p-5 bg-white">
                        <p className="text-sm text-slate-600">
                          Decision recorded on
                        </p>
                        <p className="text-sm font-bold text-slate-800 mt-0.5">
                          {formatDate(loan.updatedAt)}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </AdminLayout>
  );
}
