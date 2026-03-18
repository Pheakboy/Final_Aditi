"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../context/AuthContext";
import UserLayout from "../../components/UserLayout";
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

  const _today = new Date();
  const _oneMonthAgo = new Date(_today);
  _oneMonthAgo.setMonth(_oneMonthAgo.getMonth() - 1);
  const [dateFrom, setDateFrom] = useState(
    _oneMonthAgo.toISOString().slice(0, 10),
  );
  const [dateTo, setDateTo] = useState(_today.toISOString().slice(0, 10));

  const [formData, setFormData] = useState({
    type: "INCOME" as "INCOME" | "EXPENSE",
    amount: "",
    description: "",
  });
  const [formError, setFormError] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [exporting, setExporting] = useState(false);

  // ── Import state ────────────────────────────────────────────────────────────
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState<{
    imported: number;
    skipped: number;
    errors: string[];
  } | null>(null);
  const [uploadError, setUploadError] = useState("");

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

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!e.target.files) return;
    // Reset input so the same file can be re-selected after dismissal
    e.target.value = "";
    if (!file) return;

    setUploadError("");
    setUploadResult(null);
    setUploading(true);
    try {
      const res = await transactionApi.importFile(file);
      setUploadResult(res.data.data);
      fetchTransactions();
    } catch (err: unknown) {
      setUploadError(
        axios.isAxiosError(err)
          ? (err.response?.data?.message ??
              "Import failed. Please check your file format.")
          : "Import failed. Please check your file format.",
      );
    } finally {
      setUploading(false);
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
    <UserLayout title="Transactions" subtitle="Manage your income and expenses">
      <div className="p-6 lg:p-8">
        {/* Action bar */}
        <div className="flex items-center justify-end mb-8 gap-3 animate-fade-in">
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

          {/* Hidden file input */}
          <input
            ref={fileInputRef}
            type="file"
            accept=".xlsx,.xls,.csv,.pdf"
            className="hidden"
            onChange={handleImport}
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={uploading}
            className="flex items-center gap-2 px-4 py-2 bg-white border border-teal-300 text-teal-700 text-sm font-medium rounded-xl hover:bg-teal-50 transition-colors disabled:opacity-50 card-shadow"
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
                d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l4-4m0 0l4 4m-4-4v12"
              />
            </svg>
            {uploading ? "Importing..." : "Import from Bank"}
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

        {dataError && <ErrorAlert message={dataError} />}

        {/* Import error banner */}
        {uploadError && (
          <div className="mb-6 flex items-start gap-3 bg-red-50 border border-red-200 text-red-700 rounded-xl px-4 py-3 text-sm">
            <svg
              className="w-4 h-4 mt-0.5 shrink-0"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 9v2m0 4h.01M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"
              />
            </svg>
            <span>{uploadError}</span>
            <button
              onClick={() => setUploadError("")}
              className="ml-auto text-red-400 hover:text-red-600"
            >
              ✕
            </button>
          </div>
        )}

        {/* Import success banner */}
        {uploadResult && (
          <div className="mb-6 bg-emerald-50 border border-emerald-200 rounded-xl px-4 py-3 text-sm">
            <div className="flex items-center justify-between mb-1">
              <div className="flex items-center gap-2 text-emerald-700 font-semibold">
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
                    d="M5 13l4 4L19 7"
                  />
                </svg>
                Import complete — {uploadResult.imported} transaction
                {uploadResult.imported !== 1 ? "s" : ""} imported
                {uploadResult.skipped > 0 &&
                  `, ${uploadResult.skipped} skipped`}
              </div>
              <button
                onClick={() => setUploadResult(null)}
                className="text-emerald-400 hover:text-emerald-600"
              >
                ✕
              </button>
            </div>
            {uploadResult.errors.length > 0 && (
              <ul className="mt-1 pl-4 list-disc text-xs text-amber-700 space-y-0.5">
                {uploadResult.errors.map((e, i) => (
                  <li key={i}>{e}</li>
                ))}
              </ul>
            )}
          </div>
        )}

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
      </div>
    </UserLayout>
  );
}
