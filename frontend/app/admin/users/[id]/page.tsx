"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useAuth } from "../../../../context/AuthContext";
import Sidebar from "../../../../components/Sidebar";
import RiskBadge from "../../../../components/RiskBadge";
import { adminApi } from "../../../../services/api";
import { UserProfile, Loan, Transaction } from "../../../../types";
import { formatCurrency, formatDate } from "../../../../utils/format";
import axios from "axios";

export default function AdminUserDetailPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const params = useParams();
  const userId = params.id as string;

  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [dataLoading, setDataLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(false);
  const [success, setSuccess] = useState("");
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState<"loans" | "transactions">("loans");

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchProfile = async () => {
    setDataLoading(true);
    try {
      const res = await adminApi.getUserProfile(userId);
      setProfile(res.data.data);
    } catch { setError("Failed to load user profile."); }
    finally { setDataLoading(false); }
  };

  useEffect(() => { if (user && isAdmin && userId) fetchProfile(); }, [user, isAdmin, userId]);

  const handleDeactivate = async () => {
    setActionLoading(true); setError(""); setSuccess("");
    try {
      await adminApi.deactivateUser(userId);
      setSuccess("User deactivated successfully.");
      await fetchProfile();
    } catch (err: unknown) {
      setError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Action failed") : "Action failed");
    } finally { setActionLoading(false); }
  };

  const handleReactivate = async () => {
    setActionLoading(true); setError(""); setSuccess("");
    try {
      await adminApi.reactivateUser(userId);
      setSuccess("User reactivated successfully.");
      await fetchProfile();
    } catch (err: unknown) {
      setError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Action failed") : "Action failed");
    } finally { setActionLoading(false); }
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
        <div className="animate-fade-in">
          <button onClick={() => router.back()} className="flex items-center gap-2 text-slate-400 hover:text-white text-sm mb-3 transition-colors">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
            </svg>
            Back to Users
          </button>
          <h1 className="text-2xl font-bold text-white mb-1">User Detail</h1>
          <p className="text-slate-400 text-sm mb-8">Full profile and financial overview</p>
        </div>

        {error && <div className="bg-red-900/30 border border-red-700/50 text-red-300 px-4 py-3 rounded-xl text-sm mb-6">{error}</div>}
        {success && <div className="bg-emerald-900/30 border border-emerald-700/50 text-emerald-300 px-4 py-3 rounded-xl text-sm mb-6">{success}</div>}

        {profile && (
          <div className="space-y-6">
            {/* Profile Card */}
            <div className="bg-slate-800 rounded-2xl border border-slate-700 p-6">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-14 h-14 rounded-full gradient-indigo flex items-center justify-center text-white font-bold text-xl">
                    {profile.username?.charAt(0).toUpperCase()}
                  </div>
                  <div>
                    <div className="flex items-center gap-3">
                      <p className="text-white font-bold text-lg">{profile.username}</p>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${profile.enabled ? "bg-emerald-900/50 text-emerald-300" : "bg-red-900/50 text-red-300"}`}>
                        {profile.enabled ? "Active" : "Inactive"}
                      </span>
                    </div>
                    <p className="text-slate-400 text-sm">{profile.email}</p>
                    <p className="text-slate-500 text-xs mt-1">Role: {profile.roles?.join(", ")}</p>
                  </div>
                </div>
                <div className="flex gap-3">
                  {profile.enabled ? (
                    <button onClick={handleDeactivate} disabled={actionLoading}
                      className="px-4 py-2 bg-red-600/30 border border-red-700/50 text-red-300 text-sm font-medium rounded-xl hover:bg-red-600/50 disabled:opacity-50 transition-colors">
                      {actionLoading ? "..." : "Deactivate"}
                    </button>
                  ) : (
                    <button onClick={handleReactivate} disabled={actionLoading}
                      className="px-4 py-2 bg-emerald-600/30 border border-emerald-700/50 text-emerald-300 text-sm font-medium rounded-xl hover:bg-emerald-600/50 disabled:opacity-50 transition-colors">
                      {actionLoading ? "..." : "Reactivate"}
                    </button>
                  )}
                </div>
              </div>
            </div>

            {/* Financial Summary */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: "Total Income", value: formatCurrency(profile.totalIncome), color: "text-emerald-400" },
                { label: "Total Expenses", value: formatCurrency(profile.totalExpenses), color: "text-red-400" },
                { label: "Savings Balance", value: formatCurrency(profile.savingsBalance), color: profile.savingsBalance >= 0 ? "text-sky-400" : "text-red-400" },
                { label: "Risk Level", value: profile.latestRiskLevel ?? "N/A", color: "text-white" },
              ].map((s) => (
                <div key={s.label} className="bg-slate-800 rounded-2xl border border-slate-700 p-4">
                  <p className="text-xs text-slate-500 mb-1">{s.label}</p>
                  <p className={`text-lg font-bold ${s.color}`}>{s.value}</p>
                </div>
              ))}
            </div>

            {/* Tabs */}
            <div className="flex gap-2">
              {(["loans", "transactions"] as const).map((tab) => (
                <button key={tab} onClick={() => setActiveTab(tab)}
                  className={`px-4 py-2 text-sm font-medium rounded-xl capitalize transition-all ${activeTab === tab ? "bg-indigo-600 text-white" : "bg-slate-800 text-slate-400 border border-slate-700 hover:text-white"}`}>
                  {tab}
                </button>
              ))}
            </div>

            {/* Loan History Tab */}
            {activeTab === "loans" && (
              <div className="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-700">
                  <h2 className="text-sm font-semibold text-slate-300">Loan History</h2>
                </div>
                {profile.loans?.length === 0 ? (
                  <p className="text-slate-500 text-sm p-6">No loans found.</p>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="border-b border-slate-700">
                      <tr>
                        {["Amount", "Risk", "Status", "Applied Date", "Note"].map((h) => (
                          <th key={h} className="text-left px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-700/50">
                      {profile.loans?.map((loan: Loan) => (
                        <tr key={loan.id} className="hover:bg-slate-700/30 transition-colors">
                          <td className="px-5 py-3 font-semibold text-white">{formatCurrency(loan.loanAmount)}</td>
                          <td className="px-5 py-3"><RiskBadge level={loan.riskLevel} score={loan.riskScore} /></td>
                          <td className="px-5 py-3">
                            <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${loan.status === "APPROVED" ? "bg-emerald-900/50 text-emerald-300" : loan.status === "REJECTED" ? "bg-red-900/50 text-red-300" : "bg-amber-900/50 text-amber-300"}`}>
                              {loan.status}
                            </span>
                          </td>
                          <td className="px-5 py-3 text-slate-400 text-xs">{formatDate(loan.createdAt)}</td>
                          <td className="px-5 py-3 text-slate-400 text-xs italic">{loan.adminNote || "—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* Transaction History Tab */}
            {activeTab === "transactions" && (
              <div className="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden">
                <div className="px-6 py-4 border-b border-slate-700">
                  <h2 className="text-sm font-semibold text-slate-300">Recent Transactions</h2>
                </div>
                {profile.recentTransactions?.length === 0 ? (
                  <p className="text-slate-500 text-sm p-6">No transactions found.</p>
                ) : (
                  <div className="divide-y divide-slate-700/50">
                    {profile.recentTransactions?.map((tx: Transaction) => (
                      <div key={tx.id} className="flex items-center gap-4 px-6 py-3 hover:bg-slate-700/30 transition-colors">
                        <div className={`w-8 h-8 rounded-full flex items-center justify-center shrink-0 ${tx.type === "INCOME" ? "bg-emerald-900/50" : "bg-red-900/50"}`}>
                          <svg className={`w-4 h-4 ${tx.type === "INCOME" ? "text-emerald-400" : "text-red-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            {tx.type === "INCOME" ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 11l5-5m0 0l5 5m-5-5v12" /> : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 13l-5 5m0 0l-5-5m5 5V6" />}
                          </svg>
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-white truncate">{tx.description || tx.type}</p>
                          <p className="text-xs text-slate-500">{formatDate(tx.transactionDate)}</p>
                        </div>
                        <span className={`text-sm font-semibold shrink-0 ${tx.type === "INCOME" ? "text-emerald-400" : "text-red-400"}`}>
                          {tx.type === "INCOME" ? "+" : "-"}{formatCurrency(tx.amount)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
