"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { useAuth } from "../../../context/AuthContext";
import Sidebar from "../../../components/Sidebar";
import LoanCard from "../../../components/LoanCard";
import { loanApi } from "../../../services/api";
import { Loan } from "../../../types";

export default function LoanHistoryPage() {
  const { user, isLoading } = useAuth();
  const router = useRouter();
  const [loans, setLoans] = useState<Loan[]>([]);
  const [dataLoading, setDataLoading] = useState(false);
  const [dataError, setDataError] = useState("");
  const [filter, setFilter] = useState<
    "ALL" | "PENDING" | "APPROVED" | "REJECTED"
  >("ALL");

  useEffect(() => {
    if (!isLoading && !user) {
      router.push("/login");
    }
  }, [user, isLoading, router]);

  useEffect(() => {
    if (user) {
      setDataLoading(true);
      loanApi
        .getMyLoans()
        .then((res) => setLoans(res.data.data || []))
        .catch((err) => {
          console.error("Failed to fetch loans", err);
          setDataError("Failed to load loan history. Please refresh.");
        })
        .finally(() => setDataLoading(false));
    }
  }, [user]);

  const filteredLoans =
    filter === "ALL" ? loans : loans.filter((l) => l.status === filter);

  if (isLoading || dataLoading) {
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
        {dataError && (
          <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm mb-6">
            {dataError}
          </div>
        )}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Loan History</h1>
            <p className="text-gray-500 mt-1">
              All your loan applications and their outcomes
            </p>
          </div>
          <Link
            href="/loan/apply"
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition-colors"
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
            New Application
          </Link>
        </div>

        {/* Summary Stats */}
        <div className="grid grid-cols-3 gap-6 mb-8">
          {(["PENDING", "APPROVED", "REJECTED"] as const).map((status) => {
            const count = loans.filter((l) => l.status === status).length;
            const colors = {
              PENDING: "bg-yellow-50 border-yellow-200 text-yellow-700",
              APPROVED: "bg-green-50 border-green-200 text-green-700",
              REJECTED: "bg-red-50 border-red-200 text-red-700",
            };
            return (
              <div
                key={status}
                className={`rounded-xl border p-4 ${colors[status]}`}
              >
                <p className="text-sm font-medium">{status}</p>
                <p className="text-2xl font-bold mt-1">{count}</p>
              </div>
            );
          })}
        </div>

        {/* Filter Tabs */}
        <div className="flex gap-2 mb-6">
          {(["ALL", "PENDING", "APPROVED", "REJECTED"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-4 py-2 text-sm font-medium rounded-lg transition-colors ${
                filter === f
                  ? "bg-blue-600 text-white"
                  : "bg-white text-gray-600 border border-gray-200 hover:bg-gray-50"
              }`}
            >
              {f}{" "}
              {f === "ALL"
                ? `(${loans.length})`
                : `(${loans.filter((l) => l.status === f).length})`}
            </button>
          ))}
        </div>

        {/* Loans Grid */}
        {filteredLoans.length === 0 ? (
          <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-12 text-center">
            <svg
              className="w-12 h-12 text-gray-300 mx-auto mb-4"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={1}
                d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <p className="text-gray-500 mb-4">
              {filter === "ALL"
                ? "No loan applications yet."
                : `No ${filter.toLowerCase()} loans.`}
            </p>
            <Link
              href="/loan/apply"
              className="text-blue-600 hover:text-blue-700 text-sm font-medium"
            >
              Apply for your first loan →
            </Link>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filteredLoans.map((loan) => (
              <LoanCard key={loan.id} loan={loan} />
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
