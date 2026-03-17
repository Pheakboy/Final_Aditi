import Link from "next/link";
import { ArrowRight, ShieldCheck, Zap, TrendingUp, Star } from "lucide-react";

export default function HeroSection() {
  return (
    <section
      id="home"
      className="relative flex min-h-screen items-center overflow-hidden pt-16"
    >
      {/* Background blobs */}
      <div className="pointer-events-none absolute inset-0 -z-10">
        <div className="absolute -left-40 -top-20 h-150 w-150 rounded-full bg-teal-400/20 blur-3xl" />
        <div className="absolute -right-40 top-20 h-125 w-125 rounded-full bg-sky-400/20 blur-3xl" />
        <div className="absolute bottom-0 left-1/3 h-100 w-100 rounded-full bg-violet-400/15 blur-3xl" />
      </div>

      <div className="mx-auto w-full max-w-7xl px-6 py-20 lg:px-10 lg:py-32">
        <div className="grid items-center gap-14 lg:grid-cols-2">
          {/* Left – copy */}
          <div className="animate-slide-up">
            <div className="mb-5 flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-2 rounded-full border border-teal-200 bg-teal-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-teal-700">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-teal-500" />
                Now live — apply in minutes
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700">
                <ShieldCheck size={12} /> SOC 2 Compliant
              </span>
            </div>

            <h1 className="text-5xl font-black leading-[1.05] text-slate-900 xl:text-6xl">
              Smart Micro‑Loans
              <br />
              <span className="bg-linear-to-r from-teal-500 to-sky-500 bg-clip-text text-transparent">
                with Instant Risk{" "}
              </span>
              Scoring.
            </h1>

            <p className="mt-6 max-w-lg text-lg leading-relaxed text-slate-600">
              Apply, track, and manage loans transparently. Our system scoring
              engine evaluates your application in under 2 seconds — no hidden
              criteria, no paperwork delays.
            </p>

            <div className="mt-9 flex flex-wrap gap-4">
              <Link
                href="/register"
                className="inline-flex items-center gap-2 rounded-xl bg-slate-900 px-7 py-3.5 text-sm font-bold text-white shadow-lg shadow-slate-900/20 transition hover:-translate-y-0.5 hover:shadow-xl hover:shadow-slate-900/25"
              >
                Apply Now — It&apos;s Free <ArrowRight size={16} />
              </Link>
              <Link
                href="/login"
                className="inline-flex items-center gap-2 rounded-xl border border-slate-300 bg-white px-7 py-3.5 text-sm font-bold text-slate-700 transition hover:-translate-y-0.5 hover:border-slate-400"
              >
                Sign In to Dashboard
              </Link>
            </div>
            <div className="mt-7 flex flex-wrap gap-6">
              {[
                { icon: <Zap size={15} />, text: "Decisions in under 2 secs" },
                { icon: <ShieldCheck size={15} />, text: "256-bit encryption" },
                { icon: <TrendingUp size={15} />, text: "Full audit trail" },
              ].map(({ icon, text }) => (
                <div
                  key={text}
                  className="flex items-center gap-1.5 text-sm font-medium text-slate-500"
                >
                  <span className="text-teal-500">{icon}</span>
                  {text}
                </div>
              ))}
            </div>
          </div>

          {/* Right – mock loan card */}
          <div
            className="animate-slide-up lg:justify-self-end"
            style={{ animationDelay: "0.15s" }}
          >
            <div className="relative mx-auto w-full max-w-100">
              {/* Main card */}
              <div className="glass card-shadow rounded-3xl p-7">
                <div className="mb-5 flex items-center justify-between">
                  <div>
                    <p className="mb-0.5 text-[10px] text-slate-400">
                      Application #ADT-2024-0847
                    </p>
                    <span className="text-sm font-bold text-slate-900">
                      Loan Application
                    </span>
                  </div>
                  <span className="rounded-full bg-emerald-100 px-2.5 py-0.5 text-xs font-bold text-emerald-700">
                    ✓ Approved
                  </span>
                </div>

                <div className="space-y-4">
                  <div>
                    <p className="mb-1 text-xs text-slate-400">
                      Requested Amount
                    </p>
                    <p className="text-3xl font-black text-slate-900">
                      $5,000{" "}
                      <span className="text-sm font-semibold text-slate-400">
                        USD
                      </span>
                    </p>
                  </div>
                  <div className="h-px bg-slate-100" />
                  <div className="grid grid-cols-3 gap-3">
                    <div>
                      <p className="mb-1 text-xs text-slate-400">Risk Score</p>
                      <p className="text-lg font-black text-teal-600">82/100</p>
                    </div>
                    <div>
                      <p className="mb-1 text-xs text-slate-400">Term</p>
                      <p className="text-lg font-black text-slate-900">12 mo</p>
                    </div>
                    <div>
                      <p className="mb-1 text-xs text-slate-400">Rate</p>
                      <p className="text-lg font-black text-slate-900">8.5%</p>
                    </div>
                  </div>
                  <div className="rounded-xl bg-slate-50 p-3">
                    <div className="mb-1.5 flex justify-between text-xs">
                      <span className="text-slate-400">Risk Level</span>
                      <span className="font-semibold text-teal-600">
                        Low Risk
                      </span>
                    </div>
                    <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200">
                      <div className="h-full w-4/5 rounded-full bg-linear-to-r from-teal-400 to-sky-500" />
                    </div>
                    <div className="mt-1 flex justify-between text-[10px] text-slate-400">
                      <span>High Risk</span>
                      <span>Low Risk</span>
                    </div>
                  </div>
                  <div className="flex items-center gap-3 rounded-xl border border-emerald-100 bg-emerald-50 p-3">
                    <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-emerald-500 text-xs font-black text-white">
                      ✓
                    </div>
                    <div>
                      <p className="text-xs font-bold text-emerald-800">
                        Decision made in 1.8 seconds
                      </p>
                      <p className="text-xs text-emerald-600">
                        Funds ready for disbursement
                      </p>
                    </div>
                  </div>
                  <div className="rounded-xl bg-slate-50 p-3">
                    <div className="mb-1 flex justify-between text-xs">
                      <span className="text-slate-500">Monthly Repayment</span>
                      <span className="font-bold text-slate-900">$435.42</span>
                    </div>
                    <p className="text-[10px] text-slate-400">
                      Est. total: $5,225.04 over 12 months
                    </p>
                  </div>
                </div>
              </div>

              {/* Floating badges */}
              <div className="absolute -left-1/3 top-1/4 glass rounded-2xl px-4 py-2.5 shadow-lg">
                <p className="text-xs font-semibold text-slate-500">
                  Processed in
                </p>
                <p className="text-sm font-black text-slate-900">1.8 sec</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
