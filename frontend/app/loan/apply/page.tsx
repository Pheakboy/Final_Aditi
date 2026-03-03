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
    if (!isLoading && !user) {
      router.push("/login");
    }
  }, [user, isLoading, router]);

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
        `Loan application submitted! Risk Score: ${loan.riskScore?.toFixed(1)} (${loan.riskLevel})`,
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
          ? err.response?.data?.message ?? "Failed to submit loan application"
          : "Failed to submit loan application",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-gray-50">
      <Sidebar />
      <main className="flex-1 p-8">
        <div className="mb-8">
          <h1 className="text-2xl font-bold text-gray-900">Apply for a Loan</h1>
          <p className="text-gray-500 mt-1">
            Fill in your financial details to get a risk assessment
          </p>
        </div>

        <div className="max-w-2xl">
          {/* Risk Scoring Info */}
          <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 mb-6">
            <h3 className="text-sm font-semibold text-blue-800 mb-2">
              How Risk Scoring Works
            </h3>
            <div className="grid grid-cols-3 gap-3 text-xs text-blue-700">
              <div className="bg-white rounded-lg p-2 text-center">
                <div className="font-bold text-green-600 mb-1">LOW RISK</div>
                <div>Score ≥ 80</div>
              </div>
              <div className="bg-white rounded-lg p-2 text-center">
                <div className="font-bold text-yellow-600 mb-1">
                  MEDIUM RISK
                </div>
                <div>Score 50–79</div>
              </div>
              <div className="bg-white rounded-lg p-2 text-center">
                <div className="font-bold text-red-600 mb-1">HIGH RISK</div>
                <div>Score &lt; 50</div>
              </div>
            </div>
          </div>

          <form
            onSubmit={handleSubmit}
            className="bg-white rounded-xl shadow-sm border border-gray-200 p-8 space-y-6"
          >
            {error && (
              <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm">
                {error}
              </div>
            )}
            {success && (
              <div className="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg text-sm">
                {success}
              </div>
            )}

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Loan Amount ($) <span className="text-red-500">*</span>
              </label>
              <input
                type="number"
                step="0.01"
                min="1"
                value={formData.loanAmount}
                onChange={(e) =>
                  setFormData({ ...formData, loanAmount: e.target.value })
                }
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                placeholder="e.g. 5000"
                required
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Monthly Income ($) <span className="text-red-500">*</span>
                </label>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  value={formData.monthlyIncome}
                  onChange={(e) =>
                    setFormData({ ...formData, monthlyIncome: e.target.value })
                  }
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                  placeholder="e.g. 3000"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Monthly Expense ($) <span className="text-red-500">*</span>
                </label>
                <input
                  type="number"
                  step="0.01"
                  min="0"
                  value={formData.monthlyExpense}
                  onChange={(e) =>
                    setFormData({ ...formData, monthlyExpense: e.target.value })
                  }
                  className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                  placeholder="e.g. 1500"
                  required
                />
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Purpose (optional)
              </label>
              <textarea
                value={formData.purpose}
                onChange={(e) =>
                  setFormData({ ...formData, purpose: e.target.value })
                }
                rows={3}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm"
                placeholder="e.g. Business expansion, Home renovation, Education..."
              />
            </div>

            <button
              type="submit"
              disabled={isSubmitting}
              className="w-full py-3 px-4 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isSubmitting ? (
                <span className="flex items-center justify-center gap-2">
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
                    ></circle>
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                    ></path>
                  </svg>
                  Submitting Application...
                </span>
              ) : (
                "Submit Loan Application"
              )}
            </button>
          </form>
        </div>
      </main>
    </div>
  );
}
