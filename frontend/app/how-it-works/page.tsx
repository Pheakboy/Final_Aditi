import LandingNavbar from "../../components/landing/LandingNavbar";
import HowItWorksSection from "../../components/landing/HowItWorksSection";
import LandingFooter from "../../components/landing/LandingFooter";

export const metadata = {
  title: "How It Works — Additi Loan System",
  description:
    "Learn the four simple steps from account creation to funded loan on the Additi platform.",
};

export default function HowItWorksPage() {
  return (
    <>
      <LandingNavbar />
      <main className="pt-16">
        {/* Page header */}
        <div className="relative overflow-hidden bg-gradient-to-br from-slate-50 to-sky-50/40 py-20 text-center">
          <div className="pointer-events-none absolute inset-0">
            <div className="absolute left-1/3 -top-20 h-80 w-80 rounded-full bg-sky-400/15 blur-3xl" />
            <div className="absolute right-1/4 bottom-0 h-72 w-72 rounded-full bg-violet-400/15 blur-3xl" />
          </div>
          <div className="relative">
            <span className="inline-flex rounded-full border border-sky-200 bg-sky-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-sky-700">
              How It Works
            </span>
            <h1 className="mt-4 text-5xl font-black text-slate-900">
              From sign-up to funded loan.
            </h1>
            <p className="mx-auto mt-3 max-w-xl text-base text-slate-500">
              The entire borrowing journey is designed to be fast, transparent,
              and stress-free — just four steps.
            </p>
          </div>
        </div>

        <HowItWorksSection />
      </main>
      <LandingFooter />
    </>
  );
}
