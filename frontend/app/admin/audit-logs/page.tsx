"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import { adminApi } from "../../../services/api";

interface AuditLog {
  id: number;
  action: string;
  performedBy: string;
  targetType?: string;
  details?: string;
  ipAddress?: string;
  timestamp: string;
}

const actionColor = (action: string) => {
  if (action.includes("APPROVED") || action.includes("CREATED") || action.includes("REACTIVATED")) return "bg-emerald-900/40 text-emerald-300";
  if (action.includes("REJECTED") || action.includes("DEACTIVATED") || action.includes("DELETED")) return "bg-red-900/40 text-red-300";
  if (action.includes("UPDATED") || action.includes("SENT") || action.includes("EXPORTED")) return "bg-sky-900/40 text-sky-300";
  return "bg-slate-700/50 text-slate-300";
};

export default function AuditLogsPage() {
  const { user, isLoading, isAdmin } = useAuth();
  const router = useRouter();
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [actionFilter, setActionFilter] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [page, setPage] = useState(0);
  const [totalPages, setTotalPages] = useState(0);
  const [totalElements, setTotalElements] = useState(0);
  const PAGE_SIZE = 15;

  useEffect(() => {
    if (!isLoading && !user) router.push("/login");
    if (!isLoading && user && !isAdmin) router.push("/dashboard");
  }, [user, isLoading, isAdmin, router]);

  const fetchLogs = useCallback(async (p = 0) => {
    setDataLoading(true);
    try {
      const res = await adminApi.getAuditLogs({
        page: p, size: PAGE_SIZE,
        action: actionFilter || undefined,
        from: dateFrom || undefined,
        to: dateTo || undefined,
      });
      const data = res.data.data;
      if (data?.content) {
        setLogs(data.content);
        setPage(data.page ?? p);
        setTotalPages(data.totalPages ?? 1);
        setTotalElements(data.totalElements ?? 0);
      } else {
        setLogs(Array.isArray(data) ? data : []);
        setTotalPages(1);
      }
    } catch { /* silently handle */ }
    finally { setDataLoading(false); }
  }, [actionFilter, dateFrom, dateTo]);

  useEffect(() => { if (user && isAdmin) { setPage(0); fetchLogs(0); } }, [user, isAdmin, actionFilter, dateFrom, dateTo]);

  const formatTs = (ts: string) => new Date(ts).toLocaleString();

  if (isLoading) return (
    <div className="flex min-h-screen items-center justify-center bg-slate-900">
      <div className="animate-spin rounded-full h-10 w-10 border-2 border-indigo-500 border-t-transparent" />
    </div>
  );

  return (
    <div className="flex min-h-screen bg-slate-900">
      <Sidebar />
      <main className="flex-1 p-6 lg:p-8 overflow-auto admin-scroll">
        <div className="mb-8 animate-fade-in">
          <h1 className="text-2xl font-bold text-white">Audit Logs</h1>
          <p className="text-slate-400 mt-1 text-sm">{totalElements} events recorded · Read-only</p>
        </div>

        {/* Filters */}
        <div className="bg-slate-800 rounded-2xl border border-slate-700 p-4 mb-6">
          <div className="flex flex-wrap gap-4 items-center">
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400 font-medium">Action contains:</label>
              <input type="text" value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}
                className="px-3 py-1.5 text-sm bg-slate-900/60 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500"
                placeholder="e.g. LOAN, USER..." />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400 font-medium">From:</label>
              <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)}
                className="px-3 py-1.5 text-sm bg-slate-900/60 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-indigo-500" />
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400 font-medium">To:</label>
              <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)}
                className="px-3 py-1.5 text-sm bg-slate-900/60 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-indigo-500" />
            </div>
            {(actionFilter || dateFrom || dateTo) && (
              <button onClick={() => { setActionFilter(""); setDateFrom(""); setDateTo(""); }}
                className="px-3 py-1.5 text-xs font-medium text-red-400 bg-red-900/30 border border-red-700/50 rounded-lg hover:bg-red-900/50 transition-colors">
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Table */}
        <div className="bg-slate-800 rounded-2xl border border-slate-700 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="border-b border-slate-700">
              <tr>
                {["Action", "Performed By", "Target", "IP Address", "Timestamp"].map((h) => (
                  <th key={h} className="text-left px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {dataLoading ? (
                <tr><td colSpan={5} className="text-center py-12">
                  <div className="animate-spin rounded-full h-8 w-8 border-2 border-indigo-500 border-t-transparent mx-auto" />
                </td></tr>
              ) : logs.length === 0 ? (
                <tr><td colSpan={5} className="text-center py-12 text-slate-500 text-sm">No audit logs found</td></tr>
              ) : logs.map((log) => (
                <tr key={log.id} className="hover:bg-slate-700/30 transition-colors">
                  <td className="px-5 py-3">
                    <span className={`text-xs font-semibold px-2.5 py-1 rounded-full ${actionColor(log.action)}`}>{log.action}</span>
                  </td>
                  <td className="px-5 py-3 text-slate-300 text-sm">{log.performedBy}</td>
                  <td className="px-5 py-3 text-slate-400 text-xs">{log.targetType || "—"}</td>
                  <td className="px-5 py-3 text-slate-400 text-xs font-mono">{log.ipAddress || "—"}</td>
                  <td className="px-5 py-3 text-slate-400 text-xs whitespace-nowrap">{formatTs(log.timestamp)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between mt-6">
            <p className="text-sm text-slate-500">Page {page + 1} of {totalPages} · {totalElements} total</p>
            <div className="flex gap-2">
              <button onClick={() => fetchLogs(page - 1)} disabled={page === 0}
                className="px-3 py-1.5 text-sm border border-slate-700 rounded-lg bg-slate-800 text-slate-400 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors">‹ Prev</button>
              <button onClick={() => fetchLogs(page + 1)} disabled={page >= totalPages - 1}
                className="px-3 py-1.5 text-sm border border-slate-700 rounded-lg bg-slate-800 text-slate-400 hover:text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors">Next ›</button>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
