"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../context/AuthContext";
import Sidebar from "../../components/Sidebar";
import LoadingScreen from "../../components/ui/LoadingScreen";
import ErrorAlert from "../../components/ui/ErrorAlert";
import AddTransactionForm from "../../components/transactions/AddTransactionForm";
import TransactionFilters from "../../components/transactions/TransactionFilters";
import TransactionList from "../../components/transactions/TransactionList";
import { transactionApi } from "../../services/api";
import { Transaction } from "../../types";
import { formatCurrency } from "../../utils/format";
import axios from "axios";

export default function TransactionsPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [transactions, setTransactions] = useState<Transaction[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [typeFilter, setTypeFilter] = useState<"ALL" | "INCOME" | "EXPENSE">(
    "ALL",
  );
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [formData, setFormData] = useState({
    type: "INCOME" as "INCOME" | "EXPENSE",
    amount: "",
    description: "",
  });
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
      await transactionApi.add({
        type: formData.type,
        amount: parseFloat(formData.amount),
        description: formData.description || undefined,
      });
      setFormData({ type: "INCOME", amount: "", description: "" });
      setShowForm(false);
      fetchTransactions();
    } catch (err: unknown) {
      setFormError(
        axios.isAxiosError(err)
          ? (err.response?.data?.message ?? "Failed to add transaction")
          : "Failed to add transaction",
      );
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

  const totalIncome = transactions
    .filter((t) => t.type === "INCOME")
    .reduce((s, t) => s + t.amount, 0);
  const totalExpense = transactions
    .filter((t) => t.type === "EXPENSE")
    .reduce((s, t) => s + t.amount, 0);
  const netBalance = totalIncome - totalExpense;

  if (isLoading) {
    return <LoadingScreen color="border-teal-500" />;
  }

  return (
    <div className="flex min-h-screen bg-slate-50">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-8 overflow-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-8 animate-fade-in">
          <div>
            <h1 className="text-2xl font-bold text-slate-900">Transactions</h1>
            <p className="text-slate-500 mt-1 text-sm">
              Manage your income and expenses
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={handleExport}
              disabled={exporting}
              className="flex items-center gap-2 px-4 py-2 bg-white border border-slate-200 text-slate-600 text-sm font-medium rounded-xl hover:bg-slate-50 transition-colors disabled:opacity-50 card-shadow"
            >
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
                  d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                />
              </svg>
              {exporting ? "Exporting..." : "Export CSV"}
            </button>
            <button
              onClick={() => setShowForm(!showForm)}
              className="flex items-center gap-2 px-4 py-2 gradient-teal text-white text-sm font-semibold rounded-xl shadow-sm hover:opacity-90 transition-all"
            >
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
                  d="M12 4v16m8-8H4"
                />
              </svg>
              Add Transaction
            </button>
          </div>
        </div>

        {dataError && <ErrorAlert message={dataError} />}

        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-5 mb-8">
          {[
            {
              label: "Total Income",
              value: formatCurrency(totalIncome),
              color: "text-emerald-600",
              iconBg: "gradient-emerald",
              arrow: "up",
            },
            {
              label: "Total Expenses",
              value: formatCurrency(totalExpense),
              color: "text-red-500",
              iconBg: "gradient-rose",
              arrow: "down",
            },
            {
              label: "Net Balance",
              value: formatCurrency(netBalance),
              color: netBalance >= 0 ? "text-sky-600" : "text-red-500",
              iconBg: "gradient-sky",
              arrow: "both",
            },
          ].map((card) => (
            <div
              key={card.label}
              className="bg-white rounded-2xl card-shadow p-5 flex items-start gap-4"
            >
              <div
                className={`${card.iconBg} w-10 h-10 rounded-xl flex items-center justify-center shrink-0`}
              >
                <svg
                  className="w-5 h-5 text-white"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  {card.arrow === "up" && (
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M7 11l5-5m0 0l5 5m-5-5v12"
                    />
                  )}
                  {card.arrow === "down" && (
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M17 13l-5 5m0 0l-5-5m5 5V6"
                    />
                  )}
                  {card.arrow === "both" && (
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"
                    />
                  )}
                </svg>
              </div>
              <div>
                <p className="text-xs text-slate-500 mb-0.5">{card.label}</p>
                <p className={`text-xl font-bold ${card.color}`}>
                  {card.value}
                </p>
              </div>
            </div>
          ))}
        </div>

        {/* Add Transaction Form */}
        {showForm && (
          <AddTransactionForm
            formData={formData}
            formError={formError}
            isSubmitting={isSubmitting}
            onFormChange={setFormData}
            onSubmit={handleSubmit}
            onCancel={() => {
              setShowForm(false);
              setFormError("");
            }}
          />
        )}

        <TransactionFilters
          typeFilter={typeFilter}
          dateFrom={dateFrom}
          dateTo={dateTo}
          onTypeFilterChange={setTypeFilter}
          onDateFromChange={setDateFrom}
          onDateToChange={setDateTo}
        />

        <TransactionList transactions={transactions} isLoading={dataLoading} />
      </main>
    </div>
  );
}
