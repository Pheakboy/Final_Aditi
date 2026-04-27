"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import AdminLayout from "../../../components/admin/AdminLayout";
import { adminApi } from "../../../services/api";
import { PagedResponse } from "../../../types";
import LoadingScreen from "../../../components/ui/LoadingScreen";
import ErrorAlert from "../../../components/ui/ErrorAlert";
import Pagination from "../../../components/ui/Pagination";
import { formatCurrency, formatDate } from "../../../utils/format";
import { useToast } from "../../../components/ui/Toast";

type TypeFilter = "" | "INCOME" | "EXPENSE";

interface AdminTransaction {
  id: string;
  userId: number;
  username: string;
  email: string;
  type: "INCOME" | "EXPENSE";
  amount: number;
  description?: string;
  transactionDate: string;
  createdAt: string;
}

interface SystemStats {
  total: number;
  income: number;
  expense: number;
}

export default function AdminTransactionsPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const { showToast } = useToast();

  const [transactions, setTransactions] = useState<AdminTransaction[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [typeFilter, setTypeFilter] = useState<TypeFilter>("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [search, setSearch] = useState("");
  const [currentPage, setCurrentPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [totalElements, setTotalElements] = useState(0);
  const PAGE_SIZE = 20;

  const [stats, setStats] = useState<SystemStats>({
    total: 0,
    income: 0,
    expense: 0,
  });
  const [statsLoading, setStatsLoading] = useState(true);

  const [deleteTarget, setDeleteTarget] = useState<AdminTransaction | null>(
    null,
  );
  const [deletingId, setDeletingId] = useState<string | null>(null);

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchStats = useCallback(async () => {
    setStatsLoading(true);
    try {
      const [allRes, incomeRes, expenseRes] = await Promise.all([
        adminApi.getAllTransactions({ page: 0, size: 1 }),
        adminApi.getAllTransactions({ page: 0, size: 1, type: "INCOME" }),
        adminApi.getAllTransactions({ page: 0, size: 1, type: "EXPENSE" }),
      ]);
      setStats({
        total: (allRes.data.data as PagedResponse<AdminTransaction>)
          .totalElements,
        income: (incomeRes.data.data as PagedResponse<AdminTransaction>)
          .totalElements,
        expense: (expenseRes.data.data as PagedResponse<AdminTransaction>)
          .totalElements,
      });
    } catch {
      // stats are non-critical
    } finally {
      setStatsLoading(false);
    }
  }, []);

  const fetchTransactions = useCallback(
    async (page = 0) => {
      setDataLoading(true);
      setDataError("");
      try {
        const res = await adminApi.getAllTransactions({
          page,
          size: PAGE_SIZE,
          type: typeFilter || undefined,
          from: dateFrom || undefined,
          to: dateTo || undefined,
          search: search || undefined,
        });
        const paged: PagedResponse<AdminTransaction> = res.data.data;
        setTransactions(paged.content || []);
        setCurrentPage(paged.page);
        setTotalPages(paged.totalPages);
        setTotalElements(paged.totalElements);
      } catch {
        setDataError("Failed to load transactions. Please refresh.");
      } finally {
        setDataLoading(false);
      }
    },
    [typeFilter, dateFrom, dateTo, search],
  );

  useEffect(() => {
    if (user && isAdmin) fetchStats();
  }, [user, isAdmin, fetchStats]);

  useEffect(() => {
    if (user && isAdmin) {
      setCurrentPage(0);
      fetchTransactions(0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, isAdmin, typeFilter, dateFrom, dateTo, search]);

  const handleDelete = async () => {
    if (!deleteTarget) return;
    const id = deleteTarget.id;
    setDeletingId(id);
    setDeleteTarget(null);
    try {
      await adminApi.deleteTransaction(id);
      showToast("Transaction deleted successfully", "success");
      await Promise.all([fetchTransactions(currentPage), fetchStats()]);
    } catch {
      showToast("Failed to delete transaction. Please try again.", "error");
    } finally {
      setDeletingId(null);
    }
  };

  const clearFilters = () => {
    setTypeFilter("");
    setDateFrom("");
    setDateTo("");
    setSearchInput("");
    setSearch("");
    setCurrentPage(0);
  };

  const hasFilters = typeFilter || dateFrom || dateTo || search;

  const displayed = transactions;

  if (isLoading) return <LoadingScreen color="border-indigo-500" />;

  return (
    <AdminLayout
      title="Transaction Management"
      subtitle="View and manage all financial transactions across the platform"
      onRefresh={() => {
        fetchTransactions(currentPage);
        fetchStats();
      }}
    >
      <div className="p-6 lg:p-8 space-y-6">
        {dataError && <ErrorAlert message={dataError} />}

        {/* -- System-wide Stats ------------------------------------------- */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {/* Total */}
          <div className="bg-white rounded-xl border border-slate-200 p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-gray-500">
                Total Transactions
              </p>
              <div className="w-8 h-8 rounded-lg bg-slate-100 flex items-center justify-center">
                <svg
                  className="w-4 h-4 text-slate-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"
                  />
                </svg>
              </div>
            </div>
            {statsLoading ? (
              <div className="h-8 bg-gray-100 rounded animate-pulse w-16" />
            ) : (
              <p className="text-3xl font-bold text-slate-900">
                {stats.total.toLocaleString()}
              </p>
            )}
          </div>

          {/* Income */}
          <div className="bg-white rounded-xl border border-emerald-200 p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-emerald-600">
                Income Records
              </p>
              <div className="w-8 h-8 rounded-lg bg-emerald-50 flex items-center justify-center">
                <svg
                  className="w-4 h-4 text-emerald-600"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2.5}
                    d="M7 11l5-5m0 0l5 5m-5-5v12"
                  />
                </svg>
              </div>
            </div>
            {statsLoading ? (
              <div className="h-8 bg-gray-100 rounded animate-pulse w-16" />
            ) : (
              <p className="text-3xl font-bold text-emerald-700">
                {stats.income.toLocaleString()}
              </p>
            )}
          </div>

          {/* Expense */}
          <div className="bg-white rounded-xl border border-red-200 p-5 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs font-semibold uppercase tracking-wider text-red-500">
                Expense Records
              </p>
              <div className="w-8 h-8 rounded-lg bg-red-50 flex items-center justify-center">
                <svg
                  className="w-4 h-4 text-red-500"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2.5}
                    d="M17 13l-5 5m0 0l-5-5m5 5V6"
                  />
                </svg>
              </div>
            </div>
            {statsLoading ? (
              <div className="h-8 bg-gray-100 rounded animate-pulse w-16" />
            ) : (
              <p className="text-3xl font-bold text-red-700">
                {stats.expense.toLocaleString()}
              </p>
            )}
          </div>
        </div>

        {/* -- Filters ---------------------------------------------------- */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-4">
          <div className="flex flex-col lg:flex-row lg:items-end gap-4">
            {/* Type filter pills */}
            <div className="flex gap-2 flex-wrap">
              {(
                [
                  { value: "" as TypeFilter, label: "All Types" },
                  { value: "INCOME" as TypeFilter, label: "Income" },
                  { value: "EXPENSE" as TypeFilter, label: "Expense" },
                ] as const
              ).map(({ value, label }) => (
                <button
                  key={value}
                  onClick={() => {
                    setTypeFilter(value);
                    setCurrentPage(0);
                  }}
                  className={`px-3.5 py-1.5 rounded-lg text-sm font-medium border transition-all ${
                    typeFilter === value
                      ? value === ""
                        ? "bg-slate-900 text-white border-transparent"
                        : value === "INCOME"
                          ? "bg-emerald-600 text-white border-transparent"
                          : "bg-red-600 text-white border-transparent"
                      : "bg-white text-gray-600 border-gray-200 hover:bg-gray-50"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* Date range */}
            <div className="flex gap-3 items-end flex-wrap">
              <div>
                <label className="block text-xs text-gray-500 mb-1 font-medium">
                  From
                </label>
                <input
                  type="date"
                  value={dateFrom}
                  onChange={(e) => {
                    setDateFrom(e.target.value);
                    setCurrentPage(0);
                  }}
                  className="px-3 py-1.5 border border-gray-200 rounded-lg text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-200"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-500 mb-1 font-medium">
                  To
                </label>
                <input
                  type="date"
                  value={dateTo}
                  onChange={(e) => {
                    setDateTo(e.target.value);
                    setCurrentPage(0);
                  }}
                  className="px-3 py-1.5 border border-gray-200 rounded-lg text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-200"
                />
              </div>
            </div>

            {/* Search + clear */}
            <div className="flex gap-2 lg:ml-auto">
              <div className="relative">
                <svg
                  className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400"
                  fill="none"
                  viewBox="0 0 24 24"
                  stroke="currentColor"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"
                  />
                </svg>
                <input
                  type="text"
                  placeholder="Search by user�"
                  value={searchInput}
                  onChange={(e) => setSearchInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") setSearch(searchInput);
                  }}
                  className="pl-9 pr-3 py-1.5 border border-gray-200 rounded-lg text-sm text-gray-700 w-48 focus:outline-none focus:ring-2 focus:ring-indigo-200"
                />
              </div>
              <button
                onClick={() => setSearch(searchInput)}
                className="px-3 py-1.5 bg-indigo-600 text-white rounded-lg text-sm font-medium hover:bg-indigo-700 transition-colors"
              >
                Search
              </button>
              {hasFilters && (
                <button
                  onClick={clearFilters}
                  className="px-3 py-1.5 border border-gray-200 rounded-lg text-sm text-gray-500 hover:bg-gray-50 transition-colors"
                >
                  Clear
                </button>
              )}
            </div>
          </div>
        </div>

        {/* -- Table ------------------------------------------------------ */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-100">
            <span className="text-sm font-medium text-gray-700">
              {dataLoading
                ? "Loading�"
                : `${totalElements.toLocaleString()} transaction${totalElements !== 1 ? "s" : ""}${typeFilter ? ` � ${typeFilter}` : ""}${search ? ` � matching "${search}"` : ""}`}
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50/80 border-b border-gray-100">
                <tr>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    User
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Type
                  </th>
                  <th className="text-right px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Amount
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Description
                  </th>
                  <th className="text-left px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider">
                    Date
                  </th>
                  <th className="px-5 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wider text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {dataLoading ? (
                  Array.from({ length: 8 }).map((_, i) => (
                    <tr key={i} className="animate-pulse">
                      {Array.from({ length: 6 }).map((__, j) => (
                        <td key={j} className="px-5 py-4">
                          <div
                            className="h-3.5 bg-gray-100 rounded"
                            style={{ width: `${60 + ((j * 13) % 40)}%` }}
                          />
                        </td>
                      ))}
                    </tr>
                  ))
                ) : displayed.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-5 py-16 text-center">
                      <div className="flex flex-col items-center gap-3">
                        <svg
                          className="w-12 h-12 text-gray-200"
                          fill="none"
                          viewBox="0 0 24 24"
                          stroke="currentColor"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={1.5}
                            d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z"
                          />
                        </svg>
                        <p className="text-sm font-medium text-gray-500">
                          No transactions found
                        </p>
                        <p className="text-xs text-gray-400">
                          {search
                            ? `No results for "${search}" � try a different search`
                            : typeFilter || dateFrom || dateTo
                              ? "Try adjusting your filters or date range"
                              : "No transaction records exist yet"}
                        </p>
                      </div>
                    </td>
                  </tr>
                ) : (
                  displayed.map((tx) => (
                    <tr
                      key={tx.id}
                      className="hover:bg-gray-50/60 transition-colors"
                    >
                      {/* User */}
                      <td className="px-5 py-3.5">
                        <p className="font-medium text-gray-900">
                          {tx.username}
                        </p>
                        <p className="text-xs text-gray-400 mt-0.5">
                          {tx.email}
                        </p>
                      </td>
                      {/* Type */}
                      <td className="px-5 py-3.5">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-semibold ${
                            tx.type === "INCOME"
                              ? "bg-emerald-50 text-emerald-700 border border-emerald-200"
                              : "bg-red-50 text-red-700 border border-red-200"
                          }`}
                        >
                          {tx.type === "INCOME" ? (
                            <svg
                              className="w-3 h-3"
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2.5}
                                d="M7 11l5-5m0 0l5 5m-5-5v12"
                              />
                            </svg>
                          ) : (
                            <svg
                              className="w-3 h-3"
                              fill="none"
                              viewBox="0 0 24 24"
                              stroke="currentColor"
                            >
                              <path
                                strokeLinecap="round"
                                strokeLinejoin="round"
                                strokeWidth={2.5}
                                d="M17 13l-5 5m0 0l-5-5m5 5V6"
                              />
                            </svg>
                          )}
                          {tx.type}
                        </span>
                      </td>
                      {/* Amount */}
                      <td className="px-5 py-3.5 text-right">
                        <span
                          className={`font-semibold ${
                            tx.type === "INCOME"
                              ? "text-emerald-700"
                              : "text-red-600"
                          }`}
                        >
                          {tx.type === "INCOME" ? "+" : "-"}
                          {formatCurrency(tx.amount)}
                        </span>
                      </td>
                      {/* Description */}
                      <td className="px-5 py-3.5 text-gray-600 max-w-xs">
                        <p className="truncate">
                          {tx.description ? (
                            tx.description
                          ) : (
                            <span className="text-gray-300 italic">
                              No description
                            </span>
                          )}
                        </p>
                      </td>
                      {/* Date */}
                      <td className="px-5 py-3.5 text-gray-600 text-sm whitespace-nowrap">
                        {formatDate(tx.transactionDate)}
                      </td>
                      {/* Actions */}
                      <td className="px-5 py-3.5 text-right">
                        {deletingId === tx.id ? (
                          <span className="w-4 h-4 border-2 border-red-300 border-t-red-600 rounded-full animate-spin inline-block" />
                        ) : (
                          <button
                            onClick={() => setDeleteTarget(tx)}
                            className="px-2.5 py-1.5 text-xs font-medium rounded-lg bg-red-50 text-red-600 border border-red-100 hover:bg-red-100 transition-colors"
                          >
                            Delete
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {totalPages > 1 && (
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            totalElements={totalElements}
            onPageChange={(p) => {
              setCurrentPage(p);
              fetchTransactions(p);
            }}
          />
        )}
      </div>

      {/* -- Delete Confirmation Modal ----------------------------------- */}
      {deleteTarget && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full p-6">
            <div className="w-10 h-10 rounded-full bg-red-100 flex items-center justify-center mb-4">
              <svg
                className="w-5 h-5 text-red-600"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                />
              </svg>
            </div>
            <h2 className="text-base font-bold text-gray-900 mb-1">
              Delete Transaction
            </h2>
            <p className="text-sm text-gray-500 mb-3">
              Are you sure you want to permanently delete this transaction?
            </p>
            {/* Transaction summary */}
            <div className="bg-gray-50 rounded-xl px-4 py-3 mb-4 space-y-1.5 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">User</span>
                <span className="font-medium text-gray-900">
                  {deleteTarget.username}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Type</span>
                <span
                  className={`font-medium ${
                    deleteTarget.type === "INCOME"
                      ? "text-emerald-700"
                      : "text-red-700"
                  }`}
                >
                  {deleteTarget.type}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Amount</span>
                <span
                  className={`font-semibold ${
                    deleteTarget.type === "INCOME"
                      ? "text-emerald-700"
                      : "text-red-700"
                  }`}
                >
                  {deleteTarget.type === "INCOME" ? "+" : "-"}
                  {formatCurrency(deleteTarget.amount)}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Date</span>
                <span className="text-gray-700">
                  {formatDate(deleteTarget.transactionDate)}
                </span>
              </div>
              {deleteTarget.description && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Description</span>
                  <span className="text-gray-700 text-right max-w-45 truncate">
                    {deleteTarget.description}
                  </span>
                </div>
              )}
            </div>
            <p className="text-xs text-red-600 mb-4">
              This action cannot be undone.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setDeleteTarget(null)}
                className="flex-1 py-2.5 border border-gray-200 rounded-xl text-sm font-medium text-gray-600 hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                className="flex-1 py-2.5 bg-red-600 text-white rounded-xl text-sm font-semibold hover:bg-red-700 transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}
    </AdminLayout>
  );
}
