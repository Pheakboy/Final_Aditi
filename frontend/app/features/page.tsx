import LandingNavbar from "../../components/landing/LandingNavbar";
import FeaturesSection from "../../components/landing/FeaturesSection";
import LandingFooter from "../../components/landing/LandingFooter";

export const metadata = {
  title: "Features — Additi Loan System",
  description:
    "Discover every tool in the Additi platform: instant risk scoring, guided applications, real-time notifications, audit logs, and more.",
};

export default function FeaturesPage() {
  return (
    <>
      <LandingNavbar />
      <main className="pt-16">
        {/* Page header */}
        <div className="relative overflow-hidden  py-20 text-center">
          <div className="pointer-events-none absolute inset-0">
            <div className="absolute left-1/4 -top-20 h-80 w-80 rounded-full bg-teal-400/15 blur-3xl" />
            <div className="absolute right-1/4 bottom-0 h-72 w-72 rounded-full bg-sky-400/15 blur-3xl" />
          </div>
          <div className="relative">
            <span className="inline-flex rounded-full border border-teal-200 bg-teal-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-teal-700">
              Platform Features
            </span>
            <h1 className="mt-4 text-5xl font-black text-slate-900">
              Everything in one place.
            </h1>
            <p className="mx-auto mt-3 max-w-xl text-base text-slate-500">
              Purpose-built for micro-loan operations — powerful enough for
              lenders, simple enough for every borrower.
            </p>
          </div>
        </div>

        <FeaturesSection />
      </main>
      <LandingFooter />
    </>
  );
}
