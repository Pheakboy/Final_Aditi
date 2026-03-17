const stats = [
  { value: "1,240+", label: "Loans Funded" },
  { value: "$4.8M", label: "Total Disbursed" },
  { value: "98.2%", label: "Repayment Rate" },
  { value: "< 2 sec", label: "Avg. Decision Time" },
];

export default function AboutSection() {
  return (
    <section id="about" className="bg-white py-24">
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        <div className="grid items-center gap-12 lg:grid-cols-2">
          {/* Left – stat cards */}
          <div className="grid grid-cols-2 gap-4">
            {stats.map(({ value, label }, i) => (
              <div
                key={label}
                className="glass card-shadow rounded-2xl p-7"
                style={{ animationDelay: `${i * 0.08}s` }}
              >
                <p className="text-4xl font-black text-slate-900">{value}</p>
                <p className="mt-1 text-sm font-medium text-slate-500">
                  {label}
                </p>
              </div>
            ))}
          </div>

          {/* Right – copy */}
          <div>
            <span className="inline-flex rounded-full border border-violet-200 bg-violet-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-violet-700">
              About Additi
            </span>
            <h2 className="mt-4 text-4xl font-black text-slate-900">
              Built for communities that need access to credit.
            </h2>
            <p className="mt-5 text-base leading-relaxed text-slate-600">
              Founded in 2022, Additi was built to remove the barriers between
              underserved borrowers and the capital they need to grow. We
              believe credit decisions should be data-driven, fair, and fully
              transparent — not opaque, arbitrary, or weeks in the making.
            </p>
            <p className="mt-4 text-base leading-relaxed text-slate-600">
              Today, Additi powers the digital lending operations of over 50
              institutions across Southeast Asia, South Asia, and Sub-Saharan
              Africa. Our platform handles everything from intake to
              disbursement, with robust audit controls, real-time risk
              analytics, and compliance tooling built in from the ground up.
            </p>

            {/* Mission statement */}
            <blockquote className="mt-6 border-l-4 border-teal-400 pl-4">
              <p className="text-sm italic text-slate-500">
                &ldquo;Our mission is simple: make access to credit as easy as
                sending a message — and just as transparent.&rdquo;
              </p>
              <footer className="mt-1.5 text-xs font-bold text-slate-700">
                — Aditi R., Founder & CEO
              </footer>
            </blockquote>

            {/* Highlight pills */}
            <div className="mt-7 flex flex-wrap gap-2">
              {[
                "Open & Transparent",
                "Data-Driven",
                "Fully Auditable",
                "Fast Decisions",
                "Globally Accessible",
              ].map((tag) => (
                <span
                  key={tag}
                  className="rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-xs font-semibold text-slate-600"
                >
                  {tag}
                </span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
