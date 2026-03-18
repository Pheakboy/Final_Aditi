"use client";

import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import UserLayout from "../../../components/UserLayout";
import { loanApi } from "../../../services/api";
import axios from "axios";

type RiskLevel = "LOW" | "MEDIUM" | "HIGH";

function computeLiveRisk(
  income: number,
  expense: number,
): {
  score: number;
  level: RiskLevel;
  incomeScore: number;
  expenseScore: number;
  savingsScore: number;
} | null {
  if (!income || income <= 0) return null;
  const incomeScore = income >= 1000 ? 100 : income >= 500 ? 70 : 40;
  const ratio = expense > 0 ? expense / income : 0;
  const expenseScore = ratio < 0.5 ? 100 : ratio < 0.8 ? 70 : 30;
  const savings = income - expense;
  const savingsScore = savings >= 300 ? 100 : savings >= 100 ? 70 : 40;
  
  const score =
    incomeScore * 0.375 + expenseScore * 0.25 + savingsScore * 0.375;
  const level: RiskLevel =
    score >= 80 ? "LOW" : score >= 50 ? "MEDIUM" : "HIGH";
  return { score, level, incomeScore, expenseScore, savingsScore };
}

const riskConfig: Record<
  RiskLevel,
  { badge: string; bar: string; label: string; icon: string; desc: string }
> = {
  LOW: {
    badge: "bg-emerald-50 border-emerald-300 text-emerald-700",
    bar: "bg-emerald-500",
    label: "Low Risk",
    icon: "🛡️",
    desc: "Great financial health! Your application looks strong.",
  },
  MEDIUM: {
    badge: "bg-amber-50 border-amber-300 text-amber-700",
    bar: "bg-amber-400",
    label: "Medium Risk",
    icon: "⚠️",
    desc: "Moderate risk. Reducing expenses could improve your score.",
  },
  HIGH: {
    badge: "bg-red-50 border-red-300 text-red-700",
    bar: "bg-red-500",
    label: "High Risk",
    icon: "🚨",
    desc: "High risk. Consider increasing income or reducing expenses.",
  },
};

export default function LoanApplyPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [formData, setFormData] = useState({
    loanAmount: "",
    monthlyIncome: "",
    monthlyExpense: "",
    purpose: "",
  });
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
  }, [user, isLoading, router]);

  const liveRisk = useMemo(() => {
    const income = parseFloat(formData.monthlyIncome);
    const expense = parseFloat(formData.monthlyExpense) || 0;
    return computeLiveRisk(income, expense);
  }, [formData.monthlyIncome, formData.monthlyExpense]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    const loanAmount = parseFloat(formData.loanAmount);
    const monthlyIncome = parseFloat(formData.monthlyIncome);
    const monthlyExpense = parseFloat(formData.monthlyExpense);
    if (!loanAmount || loanAmount <= 0) {
      setError("Please enter a valid loan amount");
      return;
    }
    if (!monthlyIncome || monthlyIncome < 0) {
      setError("Please enter a valid monthly income");
      return;
    }
    if (!monthlyExpense || monthlyExpense < 0) {
      setError("Please enter a valid monthly expense");
      return;
    }
    setIsSubmitting(true);
    try {
      const res = await loanApi.apply({
        loanAmount,
        monthlyIncome,
        monthlyExpense,
        purpose: formData.purpose || undefined,
      });
      const loan = res.data.data;
      setSuccess(
        `Application submitted! Risk Score: ${loan.riskScore?.toFixed(1)} — ${loan.riskLevel}`,
      );
      setFormData({
        loanAmount: "",
        monthlyIncome: "",
        monthlyExpense: "",
        purpose: "",
      });
      setTimeout(() => router.push("/loan/status"), 2000);
    } catch (err: unknown) {
      setError(
        axios.isAxiosError(err)
          ? (err.response?.data?.message ?? "Failed to submit application")
          : "Failed to submit application",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading)
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent" />
      </div>
    );

  return (
    <UserLayout
      title="Apply for a Loan"
      subtitle="Fill in your financial details and see your risk level instantly"
    >
      <div className="p-6 lg:p-8">
        <div className="max-w-5xl mx-auto">
          {/* Alerts */}
          {error && (
            <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-5 flex items-center gap-2">
              <svg
                className="w-4 h-4 shrink-0"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z"
                  clipRule="evenodd"
                />
              </svg>
              {error}
            </div>
          )}
          {success && (
            <div className="bg-emerald-50 border border-emerald-200 text-emerald-700 px-4 py-3 rounded-xl text-sm mb-5 flex items-center gap-2">
              <svg
                className="w-4 h-4 shrink-0"
                fill="currentColor"
                viewBox="0 0 20 20"
              >
                <path
                  fillRule="evenodd"
                  d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z"
                  clipRule="evenodd"
                />
              </svg>
              {success}
            </div>
          )}

          <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 items-start">
            {/* LEFT: Form (3 cols) */}
            <div className="lg:col-span-3 space-y-5">
              {/* Single combined form card */}
              <div className="bg-white rounded-2xl card-shadow p-6">
                <form
                  id="loan-form"
                  onSubmit={handleSubmit}
                  className="space-y-5"
                >
                  {/* Loan Details section */}
                  <div>
                    <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full gradient-teal text-white text-[10px] flex items-center justify-center font-bold shrink-0">
                        1
                      </span>
                      Loan Details
                    </h3>
                    <div className="space-y-4">
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-1.5">
                          Loan Amount ($){" "}
                          <span className="text-red-500">*</span>
                        </label>
                        <div className="relative">
                          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm font-medium select-none">
                            $
                          </span>
                          <input
                            type="number"
                            step="0.01"
                            min="1"
                            value={formData.loanAmount}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                loanAmount: e.target.value,
                              })
                            }
                            className="w-full pl-7 pr-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                            placeholder="5000"
                            required
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-1.5">
                          Purpose{" "}
                          <span className="text-slate-400 font-normal">
                            (optional)
                          </span>
                        </label>
                        <textarea
                          value={formData.purpose}
                          onChange={(e) =>
                            setFormData({
                              ...formData,
                              purpose: e.target.value,
                            })
                          }
                          rows={3}
                          className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors resize-none"
                          placeholder="e.g. Business expansion, Home renovation, Education..."
                        />
                      </div>
                    </div>
                  </div>

                  {/* Divider */}
                  <div className="border-t border-slate-100" />

                  {/* Financial Profile section */}
                  <div>
                    <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-4 flex items-center gap-2">
                      <span className="w-5 h-5 rounded-full gradient-teal text-white text-[10px] flex items-center justify-center font-bold shrink-0">
                        2
                      </span>
                      Financial Profile
                    </h3>
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-1.5">
                          Monthly Income ($){" "}
                          <span className="text-red-500">*</span>
                        </label>
                        <div className="relative">
                          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm font-medium select-none">
                            $
                          </span>
                          <input
                            type="number"
                            step="0.01"
                            min="0"
                            value={formData.monthlyIncome}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                monthlyIncome: e.target.value,
                              })
                            }
                            className="w-full pl-7 pr-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                            placeholder="3000"
                            required
                          />
                        </div>
                      </div>
                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-1.5">
                          Monthly Expense ($){" "}
                          <span className="text-red-500">*</span>
                        </label>
                        <div className="relative">
                          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 text-sm font-medium select-none">
                            $
                          </span>
                          <input
                            type="number"
                            step="0.01"
                            min="0"
                            value={formData.monthlyExpense}
                            onChange={(e) =>
                              setFormData({
                                ...formData,
                                monthlyExpense: e.target.value,
                              })
                            }
                            className="w-full pl-7 pr-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                            placeholder="1500"
                            required
                          />
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Score breakdown mini-bars (shown when both values entered) */}
                  {liveRisk && (
                    <div className="grid grid-cols-3 gap-3">
                      {[
                        { label: "Income Score", value: liveRisk.incomeScore },
                        {
                          label: "Expense Score",
                          value: liveRisk.expenseScore,
                        },
                        {
                          label: "Savings Score",
                          value: liveRisk.savingsScore,
                        },
                      ].map((s) => (
                        <div
                          key={s.label}
                          className="bg-slate-50 border border-slate-100 rounded-xl p-3"
                        >
                          <p className="text-[10px] text-slate-400 uppercase tracking-wide mb-1">
                            {s.label}
                          </p>
                          <p className="text-base font-bold text-slate-800">
                            {s.value}
                            <span className="text-xs text-slate-400 font-normal">
                              /100
                            </span>
                          </p>
                          <div className="mt-1.5 h-1 bg-slate-200 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-teal-500 rounded-full transition-all duration-500"
                              style={{ width: `${s.value}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </form>
              </div>

              {/* Submit button */}
              <button
                type="submit"
                form="loan-form"
                disabled={isSubmitting}
                className="w-full flex items-center justify-center gap-2 py-3 px-4 gradient-teal text-white text-sm font-semibold rounded-xl shadow-sm hover:opacity-90 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-teal-500 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
              >
                {isSubmitting ? (
                  <>
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
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      />
                    </svg>
                    Submitting...
                  </>
                ) : (
                  <>
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
                        d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
                      />
                    </svg>
                    Submit Loan Application
                  </>
                )}
              </button>
            </div>

            {/* RIGHT: Live Risk Preview (2 cols) */}
            <div className="lg:col-span-2 space-y-5">
              {/* Live Risk Card */}
              <div className="bg-white rounded-2xl card-shadow p-6">
                <div className="flex items-center justify-between mb-5">
                  <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider">
                    Live Risk Preview
                  </h3>
                  <span className="inline-flex items-center gap-1 text-xs bg-teal-50 text-teal-600 border border-teal-100 px-2 py-0.5 rounded-full font-medium">
                    <span className="w-1.5 h-1.5 rounded-full bg-teal-500 animate-pulse" />
                    Real-time
                  </span>
                </div>

                {!liveRisk ? (
                  <div className="text-center py-10">
                    <div className="w-16 h-16 rounded-full bg-slate-100 flex items-center justify-center mx-auto mb-3">
                      <svg
                        className="w-7 h-7 text-slate-300"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={1.5}
                          d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
                        />
                      </svg>
                    </div>
                    <p className="text-sm font-semibold text-slate-400">
                      Enter your monthly income
                    </p>
                    <p className="text-xs text-slate-300 mt-1">
                      to see your estimated risk level
                    </p>
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* Big risk badge */}
                    <div
                      className={`rounded-2xl border-2 p-5 text-center transition-all duration-300 ${riskConfig[liveRisk.level].badge}`}
                    >
                      <div className="text-4xl mb-2">
                        {riskConfig[liveRisk.level].icon}
                      </div>
                      <p className="text-2xl font-extrabold tracking-tight">
                        {riskConfig[liveRisk.level].label}
                      </p>
                      <p className="text-xs mt-1.5 opacity-70 leading-relaxed">
                        {riskConfig[liveRisk.level].desc}
                      </p>
                    </div>

                    {/* Score progress bar */}
                    <div>
                      <div className="flex justify-between text-xs text-slate-500 mb-1.5">
                        <span>Estimated Score</span>
                        <span className="font-bold text-slate-700">
                          {liveRisk.score.toFixed(1)}
                          <span className="text-slate-400 font-normal">
                            /100
                          </span>
                        </span>
                      </div>
                      <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-700 ${riskConfig[liveRisk.level].bar}`}
                          style={{ width: `${Math.max(liveRisk.score, 4)}%` }}
                        />
                      </div>
                      <div className="flex justify-between text-[10px] text-slate-400 mt-1">
                        <span>High Risk</span>
                        <span>Low Risk</span>
                      </div>
                    </div>

                    {/* Monthly savings */}
                    {(() => {
                      const savings =
                        parseFloat(formData.monthlyIncome) -
                        (parseFloat(formData.monthlyExpense) || 0);
                      return (
                        <div className="bg-slate-50 border border-slate-100 rounded-xl p-3 flex items-center justify-between">
                          <p className="text-xs text-slate-500">
                            Est. Monthly Savings
                          </p>
                          <p
                            className={`text-sm font-bold ${savings >= 0 ? "text-emerald-600" : "text-red-500"}`}
                          >
                            {savings < 0 ? "-" : ""}$
                            {Math.abs(savings).toFixed(2)}
                          </p>
                        </div>
                      );
                    })()}
                  </div>
                )}
              </div>

              {/* Scoring Guide */}
              <div className="bg-white rounded-2xl card-shadow p-5">
                <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-3">
                  Scoring Guide
                </h3>
                <div className="space-y-2">
                  {[
                    {
                      label: "Low Risk",
                      range: "Score ≥ 80",
                      color:
                        "bg-emerald-50 border-emerald-200 text-emerald-700",
                    },
                    {
                      label: "Medium Risk",
                      range: "Score 50–79",
                      color: "bg-amber-50 border-amber-200 text-amber-700",
                    },
                    {
                      label: "High Risk",
                      range: "Score < 50",
                      color: "bg-red-50 border-red-200 text-red-700",
                    },
                  ].map((r) => (
                    <div
                      key={r.label}
                      className={`flex justify-between items-center border rounded-lg px-3 py-2 ${r.color}`}
                    >
                      <p className="text-xs font-bold">{r.label}</p>
                      <p className="text-xs opacity-80">{r.range}</p>
                    </div>
                  ))}
                </div>
                <p className="text-[10px] text-slate-400 mt-3 leading-relaxed">
                  * Preview uses income & expense only. Final score also factors
                  in your transaction history.
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </UserLayout>
  );
}
