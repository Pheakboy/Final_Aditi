"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../context/AuthContext";
import Sidebar from "../../components/Sidebar";
import { transactionApi } from "../../services/api";
import { Transaction } from "../../types";
import { formatCurrency, formatDate } from "../../utils/format";
import axios from "axios";

export default function TransactionsPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [typeFilter, setTypeFilter] = useState<"ALL" | "INCOME" | "EXPENSE">("ALL");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [formData, setFormData] = useState({ type: "INCOME" as "INCOME" | "EXPENSE", amount: "", description: "" });
  const [formError, setFormError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
  }, [user, isLoading, router]);

  const fetchTransactions = async () => {
    setDataLoading(true);
    try {
      const params: Record<string, string> = {};
      if (typeFilter !== "ALL") params.type = typeFilter;
      if (dateFrom) params.from = dateFrom;
      if (dateTo) params.to = dateTo;
      const res = await transactionApi.getAll(params);
      setTransactions(res.data.data || []);
      setDataError("");
    } catch {
      setDataError("Failed to load transactions. Please refresh the page.");
    } finally {
      setDataLoading(false);
    }
  };

  useEffect(() => {
    if (user) fetchTransactions();
  }, [user, typeFilter, dateFrom, dateTo]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    if (!formData.amount || parseFloat(formData.amount) <= 0) {
      setFormError("Please enter a valid amount");
      return;
    }
    setIsSubmitting(true);
    try {
      await transactionApi.add({ type: formData.type, amount: parseFloat(formData.amount), description: formData.description || undefined });
      setFormData({ type: "INCOME", amount: "", description: "" });
      setShowForm(false);
      fetchTransactions();
    } catch (err: unknown) {
      setFormError(axios.isAxiosError(err) ? (err.response?.data?.message ?? "Failed to add transaction") : "Failed to add transaction");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await transactionApi.exportCSV();
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = "transactions.csv";
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      setDataError("Export failed. Please try again.");
    } finally {
      setExporting(false);
    }
  };

  const totalIncome = transactions.filter((t) => t.type === "INCOME").reduce((s, t) => s + t.amount, 0);
  const totalExpense = transactions.filter((t) => t.type === "EXPENSE").reduce((s, t) => s + t.amount, 0);
  const netBalance = totalIncome - totalExpense;

  if (isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="animate-spin rounded-full h-10 w-10 border-2 border-teal-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-8 overflow-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8 animate-fade-in">
          <div>
            <h1 className="text-2xl font-bold text-slate-900">Transactions</h1>
            <p className="text-slate-500 mt-1 text-sm">Manage your income and expenses</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleExport}
              disabled={exporting}
              className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 text-slate-600 text-sm font-medium rounded-xl hover:bg-slate-50 transition-colors disabled:opacity-50 card-shadow"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              {exporting ? "Exporting..." : "Export CSV"}
            </button>
            <button
              onClick={() => setShowForm(!showForm)}
              className="flex items-center gap-2 px-4 py-2 gradient-teal text-white text-sm font-semibold rounded-xl shadow-sm hover:opacity-90 transition-all"
            >
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
              </svg>
              Add Transaction
            </button>
          </div>
        </div>

        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-xl text-sm mb-6 flex items-center gap-2">
            <svg className="w-4 h-4 shrink-0" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
            </svg>
            {dataError}
          </div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 mb-8">
          {[
            { label: "Total Income", value: formatCurrency(totalIncome), color: "text-emerald-600", iconBg: "gradient-emerald", arrow: "up" },
            { label: "Total Expenses", value: formatCurrency(totalExpense), color: "text-red-500", iconBg: "gradient-rose", arrow: "down" },
            { label: "Net Balance", value: formatCurrency(netBalance), color: netBalance >= 0 ? "text-sky-600" : "text-red-500", iconBg: "gradient-sky", arrow: "both" },
          ].map((card) => (
            <div key={card.label} className="bg-white rounded-2xl card-shadow p-5 flex items-start gap-4">
              <div className={`${card.iconBg} w-10 h-10 rounded-xl flex items-center justify-center shrink-0`}>
                <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  {card.arrow === "up" && <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 11l5-5m0 0l5 5m-5-5v12" />}
                  {card.arrow === "down" && <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 13l-5 5m0 0l-5-5m5 5V6" />}
                  {card.arrow === "both" && <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />}
                </svg>
              </div>
              <div>
                <p className="text-xs text-slate-500 mb-0.5">{card.label}</p>
                <p className={`text-xl font-bold ${card.color}`}>{card.value}</p>
              </div>
            </div>
          ))}
        </div>

        {/* Add Transaction Form */}
        {showForm && (
          <div className="bg-white rounded-2xl card-shadow p-6 mb-6 animate-fade-in">
            <h2 className="text-sm font-semibold text-slate-900 mb-4">Add New Transaction</h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              {formError && (
                <div className="bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-xl text-sm">{formError}</div>
              )}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Type</label>
                  <select
                    value={formData.type}
                    onChange={(e) => setFormData({ ...formData, type: e.target.value as "INCOME" | "EXPENSE" })}
                    className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                  >
                    <option value="INCOME">Income</option>
                    <option value="EXPENSE">Expense</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Amount ($)</label>
                  <input
                    type="number" step="0.01" min="0.01"
                    value={formData.amount}
                    onChange={(e) => setFormData({ ...formData, amount: e.target.value })}
                    className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                    placeholder="0.00" required
                  />
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Description (optional)</label>
                <input
                  type="text" value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-4 py-2.5 border border-slate-200 rounded-xl text-sm text-slate-900 placeholder-slate-400 bg-white focus:outline-none focus:ring-2 focus:ring-teal-500 transition-colors"
                  placeholder="e.g. Salary, Rent, Groceries..."
                />
              </div>
              <div className="flex gap-3">
                <button type="submit" disabled={isSubmitting}
                  className="px-6 py-2.5 gradient-teal text-white text-sm font-semibold rounded-xl hover:opacity-90 disabled:opacity-50 transition-all">
                  {isSubmitting ? "Adding..." : "Add Transaction"}
                </button>
                <button type="button" onClick={() => { setShowForm(false); setFormError(""); }}
                  className="px-6 py-2.5 bg-slate-100 text-slate-700 text-sm font-medium rounded-xl hover:bg-slate-200 transition-colors">
                  Cancel
                </button>
              </div>
            </form>
          </div>
        )}

        {/* Filters */}
        <div className="bg-white rounded-2xl card-shadow p-4 mb-6">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Type:</span>
              {(["ALL", "INCOME", "EXPENSE"] as const).map((f) => (
                <button key={f} onClick={() => setTypeFilter(f)}
                  className={`px-3 py-1.5 text-xs font-medium rounded-lg transition-colors ${typeFilter === f ? "gradient-teal text-white" : "bg-slate-100 text-slate-600 hover:bg-slate-200"}`}>
                  {f}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Date:</span>
              <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)}
                className="px-3 py-1.5 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-500" />
              <span className="text-slate-400 text-sm">→</span>
              <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)}
                className="px-3 py-1.5 text-sm border border-slate-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-teal-500" />
              {(dateFrom || dateTo) && (
                <button onClick={() => { setDateFrom(""); setDateTo(""); }}
                  className="px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 border border-red-200 rounded-lg hover:bg-red-100 transition-colors">
                  Clear
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Transactions List */}
        <div className="bg-white rounded-2xl card-shadow overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-slate-900">Transaction History</h2>
            <span className="text-xs text-slate-400">{transactions.length} records</span>
          </div>
          {dataLoading ? (
            <div className="flex justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-2 border-teal-500 border-t-transparent" />
            </div>
          ) : transactions.length === 0 ? (
            <div className="p-12 text-center">
              <div className="w-12 h-12 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
                <svg className="w-6 h-6 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                </svg>
              </div>
              <p className="text-slate-500 text-sm mb-1">No transactions found</p>
              <p className="text-slate-400 text-xs">Try adjusting your filters or add a new transaction</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-50">
              {transactions.map((tx) => (
                <div key={tx.id} className="flex items-center gap-4 px-6 py-3 hover:bg-slate-50 transition-colors group">
                  <div className={`w-9 h-9 rounded-full flex items-center justify-center shrink-0 ${tx.type === "INCOME" ? "bg-emerald-50" : "bg-red-50"}`}>
                    <svg className={`w-4 h-4 ${tx.type === "INCOME" ? "text-emerald-500" : "text-red-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      {tx.type === "INCOME"
                        ? <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 11l5-5m0 0l5 5m-5-5v12" />
                        : <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 13l-5 5m0 0l-5-5m5 5V6" />}
                    </svg>
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-slate-800 truncate">{tx.description || (tx.type === "INCOME" ? "Income" : "Expense")}</p>
                    <p className="text-xs text-slate-400">{formatDate(tx.transactionDate)}</p>
                  </div>
                  <div className="text-right shrink-0">
                    <p className={`text-sm font-semibold ${tx.type === "INCOME" ? "text-emerald-600" : "text-red-500"}`}>
                      {tx.type === "INCOME" ? "+" : "-"}{formatCurrency(tx.amount)}
                    </p>
                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${tx.type === "INCOME" ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-600"}`}>
                      {tx.type}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
