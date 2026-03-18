"use client";

import Sidebar from "../Sidebar";
import AdminTopBar from "./AdminTopBar";

interface AdminLayoutProps {
  children: React.ReactNode;
  title: string;
  subtitle?: string;
  onRefresh?: () => void;
  /** Override the main content area background. Defaults to bg-slate-50 */
  mainBg?: string;
}

export default function AdminLayout({
  children,
  title,
  subtitle,
  onRefresh,
  mainBg = "bg-slate-50",
}: AdminLayoutProps) {
  return (
    <div className="flex h-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <AdminTopBar title={title} subtitle={subtitle} onRefresh={onRefresh} />
        <main className={`flex-1 overflow-y-auto admin-scroll ${mainBg}`}>
          {children}
        </main>
      </div>
    </div>
  );
}
