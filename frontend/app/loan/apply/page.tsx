"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import { loanApi } from "../../../services/api";
import axios from "axios";

export default function LoanApplyPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [formData, setFormData] = useState({ loanAmount: "", monthlyIncome: "", monthlyExpense: "", purpose: "" });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
  }, [user, isLoading, router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(""); setSuccess("");
    const loanAmount = parseFloat(formData.loanAmount);
    const monthlyIncome = parseFloat(formData.monthlyIncome);
    const monthlyExpense = parseFloat(formData.monthlyExpense);
    if (!loanAmount || loanAmount <= 0) { setError("Please enter a valid loan amount"); return; }
    if (!monthlyIncome || monthlyIncome < 0) { setError("Please enter a valid monthly income"); return; }
    if (!monthlyExpense || monthlyExpense < 0) { setError("Please enter a valid monthly expense"); return; }
    setIsSubmitting(true);
    try {
      const res = await loanApi.apply({ loanAmount, monthlyIncome, monthlyExpense, purpose: formData.purpose || undefined });
      const loan = res.data.data;
      setSuccess(`Application submitted! Risk Score: ${loan.riskScore?.toFixed(1)} — ${loan.riskLevel}`);
      setFormData({ loanAmount: "", monthlyIncome: "", monthlyExpense: "", purpose: "" });
      setTimeout(() => router.push("/loan/status"), 2000);
    } catch (err: unknown) {
      setError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Failed to submit application") : "Failed to submit application");
    } finally { setIsSubmitting(false); }
  };

  if (isLoading) return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50">
      <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent" />
    </div>
  );

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-8 overflow-auto">
        <div className="mb-8 animate-fade-in">
          <h1 className="text-2xl font-bold text-slate-900">Apply for a Loan</h1>
          <p className="text-slate-500 mt-1 text-sm">Fill in your financial details to get an instant risk assessment</p>
        </div>

        <div className="max-w-2xl">
          {/* Risk Info Panel */}
          <div className="bg-white rounded-2xl card-shadow p-5 mb-6">
            <h3 className="text-sm font-semibold text-slate-800 mb-3 flex items-center gap-2">
              <svg className="w-4 h-4 text-teal-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              How Risk Scoring Works
            </h3>
            <div className="grid grid-cols-3 gap-3">
              {[
                { label: "LOW RISK", range: "Score ≥ 80", color: "bg-emerald-50 border-emerald-200 text-emerald-700" },
                { label: "MEDIUM RISK", range: "Score 50–79", color: "bg-amber-50 border-amber-200 text-amber-700" },
                { label: "HIGH RISK", range: "Score < 50", color: "bg-red-50 border-red-200 text-red-700" },
              ].map((r) => (
                <div key={r.label} className={`border rounded-xl p-3 text-center ${r.color}`}>
                  <p className="text-xs font-bold mb-1">{r.label}</p>
                  <p className="text-xs">{r.range}</p>
                </div>
              ))}
            </div>
            <p className="text-xs text-slate-400 mt-3">Score is automatically calculated based on your income, expenses, and financial history.</p>
          </div>

          {/* Form */}
          <div className="bg-white rounded-2xl card-shadow p-6">
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-5 flex items-center gap-2">
                <svg className="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                </svg>
                {error}
              </div>
            )}
            {success && (
              <div className="bg-emerald-50 border border-emerald-200 text-emerald-700 px-4 py-3 rounded-xl text-sm mb-5 flex items-center gap-2">
                <svg className="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                </svg>
                {success}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Loan Amount ($) <span className="text-red-500">*</span></label>
                <input type="number" step="0.01" min="1" value={formData.loanAmount}
                  onChange={(e) => setFormData({ ...formData, loanAmount: e.target.value })}
                  className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                  placeholder="e.g. 5000" required />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Monthly Income ($) <span className="text-red-500">*</span></label>
                  <input type="number" step="0.01" min="0" value={formData.monthlyIncome}
                    onChange={(e) => setFormData({ ...formData, monthlyIncome: e.target.value })}
                    className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                    placeholder="e.g. 3000" required />
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Monthly Expense ($) <span className="text-red-500">*</span></label>
                  <input type="number" step="0.01" min="0" value={formData.monthlyExpense}
                    onChange={(e) => setFormData({ ...formData, monthlyExpense: e.target.value })}
                    className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                    placeholder="e.g. 1500" required />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Purpose (optional)</label>
                <textarea value={formData.purpose} onChange={(e) => setFormData({ ...formData, purpose: e.target.value })} rows={3}
                  className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors resize-none"
                  placeholder="e.g. Business expansion, Home renovation, Education..." />
              </div>
              <button type="submit" disabled={isSubmitting}
                className="w-full flex items-center justify-center gap-2 py-2.5 px-4 gradient-teal text-white text-sm font-semibold rounded-xl shadow-sm hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all">
                {isSubmitting ? (
                  <><svg className="animate-spin h-4 w-4" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                  </svg> Submitting...</>
                ) : "Submit Loan Application"}
              </button>
            </form>
          </div>
        </div>
      </main>
    </div>
  );
}
