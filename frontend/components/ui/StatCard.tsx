import { ReactNode } from "react";

interface StatCardProps {
  label: string;
  value: string | number;
  sub?: string;
  icon: ReactNode;
  iconBg: string;
  valueColor?: string;
}

export default function StatCard({
  label,
  value,
  sub,
  icon,
  iconBg,
  valueColor = "text-slate-900",
}: StatCardProps) {
  return (
    <div className="bg-white rounded-2xl card-shadow p-5 flex items-start gap-4">
      <div
        className={`${iconBg} w-10 h-10 rounded-xl flex items-center justify-center shrink-0`}
      >
        {icon}
      </div>
      <div className="min-w-0">
        <p className="text-xs text-slate-500 mb-0.5">{label}</p>
        <p className={`text-xl font-bold truncate ${valueColor}`}>{value}</p>
        {sub && <p className="text-xs text-slate-400 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}
