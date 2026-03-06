"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "../../../../context/AuthContext";
import Sidebar from "../../../../components/Sidebar";
import RiskBadge from "../../../../components/RiskBadge";
import { adminApi } from "../../../../services/api";
import { Loan } from "../../../../types";
import { formatCurrency, formatDate } from "../../../../utils/format";
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
      adminApi.getLoanById(loanId)
        .then((res) => setLoan(res.data.data))
        .catch(() => setError("Failed to load loan details."))
        .finally(() => setDataLoading(false));
    }
  }, [user, isAdmin, loanId]);

  const handleDecide = async (decision: "APPROVED" | "REJECTED") => {
    setProcessing(true); setError(""); setSuccess("");
    try {
      await adminApi.decideLoan(loanId, { decision, note: note || undefined });
      setSuccess(`Loan ${decision.toLowerCase()} successfully.`);
      setNote("");
      const res = await adminApi.getLoanById(loanId);
      setLoan(res.data.data);
    } catch (err: unknown) {
      setError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Action failed") : "Action failed");
    } finally { setProcessing(false); }
  };

  if (isLoading || dataLoading) return (
    <div className="flex min-h-screen items-center justify-center bg-slate-900">
      <div className="animate-spin rounded-full h-10 w-10 border-2 border-indigo-500 border-t-transparent" />
    </div>
  );

  return (
    <div className="flex min-h-screen bg-slate-900">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-8 overflow-auto admin-scroll">
        {/* Header */}
        <div className="flex items-center justify-between mb-8 animate-fade-in">
          <div>
            <button onClick={() => router.back()} className="flex items-center gap-2 text-slate-400 hover:text-white text-sm mb-3 transition-colors">
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
              </svg>
              Back to Loans
            </button>
            <h1 className="text-2xl font-bold text-white">Loan Detail</h1>
            <p className="text-slate-400 mt-1 text-sm">Full loan application information</p>
          </div>
          {loan && <RiskBadge level={loan.riskLevel} score={loan.riskScore} />}
        </div>

        {error && <div className="bg-red-900/30 border border-red-700/50 text-red-300 px-4 py-3 rounded-xl text-sm mb-6">{error}</div>}
        {success && <div className="bg-emerald-900/30 border border-emerald-700/50 text-emerald-300 px-4 py-3 rounded-xl text-sm mb-6">{success}</div>}

        {loan && (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Main Info */}
            <div className="lg:col-span-2 space-y-6">
              {/* Loan Summary */}
              <div className="bg-slate-800 rounded-2xl border border-slate-700 p-6">
                <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">Loan Information</h2>
                <div className="grid grid-cols-2 gap-4">
                  {[
                    { label: "Loan Amount", value: formatCurrency(loan.loanAmount) },
                    { label: "Status", value: (
                      <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${loan.status === "APPROVED" ? "bg-emerald-900/50 text-emerald-300" : loan.status === "REJECTED" ? "bg-red-900/50 text-red-300" : "bg-amber-900/50 text-amber-300"}`}>
                        {loan.status}
                      </span>
                    )},
                    { label: "Monthly Income", value: formatCurrency(loan.monthlyIncome) },
                    { label: "Monthly Expense", value: formatCurrency(loan.monthlyExpense) },
                    { label: "Applied Date", value: formatDate(loan.createdAt) },
                    { label: "Last Updated", value: formatDate(loan.updatedAt) },
                  ].map((item) => (
                    <div key={item.label} className="bg-slate-900/50 rounded-xl p-3">
                      <p className="text-xs text-slate-500 mb-1">{item.label}</p>
                      <div className="text-sm font-semibold text-white">{item.value}</div>
                    </div>
                  ))}
                </div>
                {loan.purpose && (
                  <div className="mt-4 bg-slate-900/50 rounded-xl p-3">
                    <p className="text-xs text-slate-500 mb-1">Purpose</p>
                    <p className="text-sm text-white">{loan.purpose}</p>
                  </div>
                )}
              </div>

              {/* Applicant Info */}
              <div className="bg-slate-800 rounded-2xl border border-slate-700 p-6">
                <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">Applicant</h2>
                <div className="flex items-center gap-4">
                  <div className="w-12 h-12 rounded-full gradient-indigo flex items-center justify-center text-white font-bold text-lg">
                    {loan.applicantUsername?.charAt(0).toUpperCase() || "?"}
                  </div>
                  <div>
                    <p className="text-white font-semibold">{loan.applicantUsername || "—"}</p>
                    <p className="text-slate-400 text-sm">{loan.applicantEmail || "—"}</p>
                  </div>
                </div>
              </div>

              {/* Admin Note (if decided) */}
              {loan.adminNote && (
                <div className="bg-slate-800 rounded-2xl border border-slate-700 p-6">
                  <h2 className="text-sm font-semibold text-slate-300 mb-3 uppercase tracking-wide">Admin Note</h2>
                  <p className="text-slate-300 italic text-sm">&ldquo;{loan.adminNote}&rdquo;</p>
                </div>
              )}
            </div>

            {/* Decision Panel */}
            <div className="space-y-6">
              {/* Risk */}
              <div className="bg-slate-800 rounded-2xl border border-slate-700 p-6">
                <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">Risk Assessment</h2>
                <RiskBadge level={loan.riskLevel} score={loan.riskScore} />
                {loan.riskScore !== undefined && (
                  <div className="mt-4">
                    <div className="flex justify-between text-xs text-slate-400 mb-1.5">
                      <span>Risk Score</span><span>{loan.riskScore?.toFixed(1)}/100</span>
                    </div>
                    <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
                      <div className={`h-full rounded-full transition-all ${loan.riskLevel === "LOW" ? "bg-emerald-500" : loan.riskLevel === "MEDIUM" ? "bg-amber-500" : "bg-red-500"}`}
                        style={{ width: `${Math.min(100, loan.riskScore ?? 0)}%` }} />
                    </div>
                  </div>
                )}
              </div>

              {/* Decision Action */}
              {loan.status === "PENDING" && (
                <div className="bg-slate-800 rounded-2xl border border-slate-700 p-6">
                  <h2 className="text-sm font-semibold text-slate-300 mb-4 uppercase tracking-wide">Make Decision</h2>
                  <div className="mb-4">
                    <label className="block text-xs text-slate-400 mb-1.5">Note for applicant (optional)</label>
                    <textarea value={note} onChange={(e) => setNote(e.target.value)} rows={3}
                      className="w-full px-3 py-2.5 bg-slate-900/50 border border-slate-600 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-none"
                      placeholder="e.g. Congratulations! / Insufficient income..." />
                  </div>
                  <div className="flex flex-col gap-3">
                    <button onClick={() => handleDecide("APPROVED")} disabled={processing}
                      className="w-full py-2.5 bg-emerald-600 text-white text-sm font-semibold rounded-xl hover:bg-emerald-700 disabled:opacity-50 transition-colors">
                      {processing ? "Processing..." : "✓ Approve Loan"}
                    </button>
                    <button onClick={() => handleDecide("REJECTED")} disabled={processing}
                      className="w-full py-2.5 bg-red-600 text-white text-sm font-semibold rounded-xl hover:bg-red-700 disabled:opacity-50 transition-colors">
                      {processing ? "Processing..." : "✗ Reject Loan"}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
