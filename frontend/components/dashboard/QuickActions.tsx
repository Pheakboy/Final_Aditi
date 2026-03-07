import Link from "next/link";

interface QuickAction {
  href: string;
  icon: React.ReactNode;
  iconBg: string;
  title: string;
  sub: string;
}

interface QuickActionsProps {
  actions: QuickAction[];
}

export default function QuickActions({ actions }: QuickActionsProps) {
  return (
    <div className="bg-white rounded-2xl card-shadow p-5">
      <h2 className="text-sm font-semibold text-slate-900 mb-4">
        Quick Actions
      </h2>
      <div className="space-y-2">
        {actions.map((action) => (
          <Link
            key={action.href}
            href={action.href}
            className="flex items-center gap-3 p-3 rounded-xl border border-slate-100 hover:border-teal-200 hover:bg-teal-50/50 transition-colors group"
          >
            <div
              className={`${action.iconBg} w-9 h-9 rounded-lg flex items-center justify-center shrink-0 group-hover:scale-105 transition-transform`}
            >
              {action.icon}
            </div>
            <div>
              <p className="text-sm font-medium text-slate-800">
                {action.title}
              </p>
              <p className="text-xs text-slate-400">{action.sub}</p>
            </div>
            <svg
              className="w-4 h-4 text-slate-300 ml-auto"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M9 5l7 7-7 7"
              />
            </svg>
          </Link>
        ))}
      </div>
    </div>
  );
}
