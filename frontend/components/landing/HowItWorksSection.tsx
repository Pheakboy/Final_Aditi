import { UserPlus, FileText, CheckCircle, Banknote } from "lucide-react";

const steps = [
  {
    num: "01",
    Icon: UserPlus,
    title: "Create Your Account",
    desc: "Sign up in under a minute. Provide basic details and verify your email to unlock the platform.",
    color: "from-teal-400 to-teal-600",
    glow: "bg-teal-400/20",
  },
  {
    num: "02",
    Icon: FileText,
    title: "Submit a Loan Request",
    desc: "Fill in the loan amount, purpose, and duration. Our guided form ensures nothing is missed.",
    color: "from-sky-400 to-sky-600",
    glow: "bg-sky-400/20",
  },
  {
    num: "03",
    Icon: CheckCircle,
    title: "Instant Risk Review",
    desc: "Our scoring engine evaluates your profile and generates a risk grade — automatically and transparently.",
    color: "from-violet-400 to-violet-600",
    glow: "bg-violet-400/20",
  },
  {
    num: "04",
    Icon: Banknote,
    title: "Receive Your Funds",
    desc: "Approved loans are processed promptly. Track disbursements and repayments right in your dashboard.",
    color: "from-emerald-400 to-emerald-600",
    glow: "bg-emerald-400/20",
  },
];

export default function HowItWorksSection() {
  return (
    <section
      id="how-it-works"
      className="bg-slate-50 py-24"
      style={{
        backgroundImage:
          "radial-gradient(circle at 70% 50%, rgba(13,148,136,0.07) 0%, transparent 60%)",
      }}
    >
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        {/* Heading */}
        <div className="mb-16 text-center">
          <span className="inline-flex rounded-full border border-sky-200 bg-sky-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-sky-700">
            How It Works
          </span>
          <h2 className="mt-4 text-4xl font-black text-slate-900">
            Four steps to your first loan.
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-base text-slate-500">
            The entire process from sign-up to funded loan is designed to be
            fast, clear, and stress-free.
          </p>
        </div>

        {/* Steps */}
        <div className="relative grid gap-8 sm:grid-cols-2 lg:grid-cols-4">
          {/* Connector line (desktop only) */}
          <div className="pointer-events-none absolute top-10 left-[12.5%] right-[12.5%] hidden h-px bg-linear-to-r from-teal-300 via-sky-300 to-emerald-300 lg:block" />

          {steps.map((step, i) => (
            <div
              key={step.num}
              className="relative flex flex-col items-center text-center"
            >
              {/* Icon circle */}
              <div
                className={`relative z-10 mb-5 flex h-20 w-20 items-center justify-center rounded-2xl bg-linear-to-br ${step.color} text-white shadow-lg`}
              >
                {/* Glow */}
                <div
                  className={`absolute inset-0 rounded-2xl ${step.glow} blur-xl`}
                />
                <step.Icon className="relative h-8 w-8" />
                <span className="absolute -right-2 -top-2 flex h-6 w-6 items-center justify-center rounded-full bg-white text-[10px] font-black text-slate-700 shadow-md">
                  {step.num}
                </span>
              </div>

              <h3 className="mb-2 text-base font-bold text-slate-900">
                {step.title}
              </h3>
              <p className="text-sm leading-relaxed text-slate-500">
                {step.desc}
              </p>

              {/* Mobile connector arrow */}
              {i < steps.length - 1 && (
                <div className="mt-6 text-slate-300 lg:hidden">↓</div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
