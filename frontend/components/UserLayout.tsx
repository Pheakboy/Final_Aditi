"use client";

import Sidebar from "./Sidebar";
import UserTopBar from "./UserTopBar";

interface UserLayoutProps {
  children: React.ReactNode;
  title: string;
  subtitle?: string;
  onRefresh?: () => void;
}

export default function UserLayout({
  children,
  title,
  subtitle,
  onRefresh,
}: UserLayoutProps) {
  return (
    <div className="flex h-screen overflow-hidden bg-slate-50">
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden min-w-0">
        <UserTopBar title={title} subtitle={subtitle} onRefresh={onRefresh} />
        <main className="flex-1 overflow-y-auto bg-slate-50">{children}</main>
      </div>
    </div>
  );
}
