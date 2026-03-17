import {
  ShieldCheck,
  Zap,
  BarChart2,
  ClipboardList,
  Bell,
  Users,
} from "lucide-react";

const features = [
  {
    icon: <Zap className="h-6 w-6" />,
    color: "bg-amber-100 text-amber-600",
    title: "Instant Risk Scoring",
    badge: "< 2 sec",
    desc: "Our proprietary scoring engine analyses income data, repayment history, and behavioural signals in real time — delivering a credit decision in under 2 seconds, 24/7.",
  },
  {
    icon: <ClipboardList className="h-6 w-6" />,
    color: "bg-teal-100 text-teal-600",
    title: "Guided Loan Application",
    badge: "Mobile-friendly",
    desc: "Smart, step-by-step forms with inline validation guide borrowers through the process — reducing errors and incomplete submissions by over 70%.",
  },
  {
    icon: <BarChart2 className="h-6 w-6" />,
    color: "bg-sky-100 text-sky-600",
    title: "Analytics Dashboard",
    badge: "Live data",
    desc: "Admins get real-time charts covering approval rates, monthly disbursement volumes, portfolio risk distribution, and repayment trends — all on one screen.",
  },
  {
    icon: <Bell className="h-6 w-6" />,
    color: "bg-violet-100 text-violet-600",
    title: "Real‑Time Notifications",
    badge: "Push + email",
    desc: "Borrowers and admins receive instant alerts when a loan status changes, a payment is due, or manual review is required — keeping everyone in sync.",
  },
  {
    icon: <ShieldCheck className="h-6 w-6" />,
    color: "bg-emerald-100 text-emerald-600",
    title: "Audit Logs & Compliance",
    badge: "SOC 2 ready",
    desc: "Every action — application edits, status changes, note updates — is logged with a timestamp and actor identity. Built for regulatory compliance from day one.",
  },
  {
    icon: <Users className="h-6 w-6" />,
    color: "bg-rose-100 text-rose-600",
    title: "Role-Based Access",
    badge: "Borrower & Admin",
    desc: "Dedicated workflows for borrowers and lender admins ensure users only access data relevant to their role — with no cross-contamination of sensitive information.",
  },
];

export default function FeaturesSection() {
  return (
    <section id="features" className="bg-white py-24">
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        {/* Heading */}
        <div className="mb-14 text-center">
          <span className="inline-flex rounded-full border border-teal-200 bg-teal-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-teal-700">
            Platform Features
          </span>
          <h2 className="mt-4 text-4xl font-black text-slate-900">
            Everything you need, nothing you don&apos;t.
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-base text-slate-500">
            Purpose-built for micro-loan operations — simple enough for the
            borrower, powerful enough for the institutional lender.
          </p>
        </div>

        {/* Feature cards */}
        <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f) => (
            <div
              key={f.title}
              className="group rounded-2xl border border-slate-100 bg-slate-50/70 p-7 transition hover:-translate-y-1 hover:border-slate-200 hover:shadow-md"
            >
              <div className="mb-4 flex items-start justify-between">
                <div
                  className={`inline-flex h-11 w-11 items-center justify-center rounded-xl ${f.color}`}
                >
                  {f.icon}
                </div>
                <span className="rounded-full border border-slate-200 bg-white px-2 py-0.5 text-[10px] font-bold text-slate-500">
                  {f.badge}
                </span>
              </div>
              <h3 className="mb-2 text-base font-bold text-slate-900">
                {f.title}
              </h3>
              <p className="text-sm leading-relaxed text-slate-500">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
