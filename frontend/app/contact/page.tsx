import LandingNavbar from "../../components/landing/LandingNavbar";
import ContactSection from "../../components/landing/ContactSection";
import LandingFooter from "../../components/landing/LandingFooter";

export const metadata = {
  title: "Contact — Additi Loan System",
  description:
    "Get in touch with the Additi team or create your free borrower account today.",
};

export default function ContactPage() {
  return (
    <>
      <LandingNavbar />
      <main className="pt-16">
        {/* Page header */}
        <div className="relative overflow-hidden bg-linear-to-br from-slate-50 to-emerald-50/40 py-20 text-center">
          <div className="pointer-events-none absolute inset-0">
            <div className="absolute left-1/3 -top-20 h-80 w-80 rounded-full bg-emerald-400/15 blur-3xl" />
            <div className="absolute right-1/4 bottom-0 h-72 w-72 rounded-full bg-sky-400/15 blur-3xl" />
          </div>
          <div className="relative">
            <span className="inline-flex rounded-full border border-emerald-200 bg-emerald-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-emerald-700">
              Get in Touch
            </span>
            <h1 className="mt-4 text-5xl font-black text-slate-900">
              We&apos;d love to hear from you.
            </h1>
            <p className="mx-auto mt-3 max-w-xl text-base text-slate-500">
              Whether you&apos;re a borrower ready to apply or an institution
              looking to partner — start here.
            </p>
          </div>
        </div>

        <ContactSection />
      </main>
      <LandingFooter />
    </>
  );
}
