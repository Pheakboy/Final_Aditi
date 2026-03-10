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
  // Convert old gradient classes to flat background classes for minimal look
  const getMinimalBg = (bgStr: string) => {
    if (bgStr.includes('emerald')) return 'bg-emerald-50 text-emerald-600 border-emerald-100';
    if (bgStr.includes('rose')) return 'bg-rose-50 text-rose-600 border-rose-100';
    if (bgStr.includes('sky')) return 'bg-sky-50 text-sky-600 border-sky-100';
    if (bgStr.includes('amber')) return 'bg-amber-50 text-amber-600 border-amber-100';
    if (bgStr.includes('indigo')) return 'bg-indigo-50 text-indigo-600 border-indigo-100';
    return 'bg-slate-50 text-slate-600 border-slate-200';
  };

  const cleanIconStyles = getMinimalBg(iconBg);

  return (
    <div className="bg-white border border-slate-200 rounded-xl shadow-sm p-5 flex flex-col justify-between gap-4 transition-all hover:shadow-md">
      <div className="flex items-start justify-between">
        <div className="min-w-0 z-10">
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">{label}</p>
          <p className={`text-3xl font-extrabold tracking-tight ${valueColor}`}>{value}</p>
          {sub && <p className="text-xs font-semibold text-slate-400 mt-2">{sub}</p>}
        </div>
        <div
          className={`${cleanIconStyles} w-10 h-10 rounded-lg flex items-center justify-center shrink-0 border`}
        >
          {icon}
        </div>
      </div>
    </div>
  );
}
