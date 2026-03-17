import LandingNavbar from "../../components/landing/LandingNavbar";
import AboutSection from "../../components/landing/AboutSection";
import LandingFooter from "../../components/landing/LandingFooter";

export const metadata = {
  title: "About — Additi Loan System",
  description:
    "Learn about Additi's mission to make micro-lending fair, data-driven, and transparent for communities worldwide.",
};

export default function AboutPage() {
  return (
    <>
      <LandingNavbar />
      <main className="pt-16">
        {/* Page header */}
        <div className="relative overflow-hidden bg-linear-to-br from-slate-50 to-violet-50/40 py-20 text-center">
          <div className="pointer-events-none absolute inset-0">
            <div className="absolute left-1/4 -top-20 h-80 w-80 rounded-full bg-violet-400/15 blur-3xl" />
            <div className="absolute right-1/3 bottom-0 h-72 w-72 rounded-full bg-teal-400/15 blur-3xl" />
          </div>
          <div className="relative">
            <span className="inline-flex rounded-full border border-violet-200 bg-violet-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-violet-700">
              About Us
            </span>
            <h1 className="mt-4 text-5xl font-black text-slate-900">
              Built to close the credit gap.
            </h1>
            <p className="mx-auto mt-3 max-w-xl text-base text-slate-500">
              Additi was created to make responsible micro-lending accessible,
              auditable, and powered by real data — not gut instinct.
            </p>
          </div>
        </div>

        <AboutSection />
      </main>
      <LandingFooter />
    </>
  );
}
