import Image from "next/image";
import Link from "next/link";

const footerLinks: Record<string, { label: string; href: string }[]> = {
  Platform: [
    { label: "Features", href: "/features" },
    { label: "How It Works", href: "/how-it-works" },
    { label: "Pricing", href: "#" },
    { label: "Security", href: "#" },
  ],
  Company: [
    { label: "About Us", href: "/about" },
    { label: "Blog", href: "#" },
    { label: "Careers", href: "#" },
    { label: "Press", href: "#" },
  ],
  Support: [
    { label: "Help Center", href: "#" },
    { label: "Contact Us", href: "/contact" },
    { label: "Status", href: "#" },
    { label: "API Docs", href: "#" },
  ],
  Legal: [
    { label: "Privacy Policy", href: "#" },
    { label: "Terms of Service", href: "#" },
    { label: "Cookie Policy", href: "#" },
    { label: "Compliance", href: "#" },
  ],
};

const socialLinks = [
  {
    label: "X / Twitter",
    href: "#",
    svg: (
      <svg
        viewBox="0 0 24 24"
        fill="currentColor"
        className="h-4 w-4"
        aria-hidden="true"
      >
        <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
      </svg>
    ),
  },
  {
    label: "LinkedIn",
    href: "#",
    svg: (
      <svg
        viewBox="0 0 24 24"
        fill="currentColor"
        className="h-4 w-4"
        aria-hidden="true"
      >
        <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z" />
      </svg>
    ),
  },
  {
    label: "GitHub",
    href: "#",
    svg: (
      <svg
        viewBox="0 0 24 24"
        fill="currentColor"
        className="h-4 w-4"
        aria-hidden="true"
      >
        <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z" />
      </svg>
    ),
  },
];

export default function LandingFooter() {
  return (
    <footer className="bg-slate-900 py-16 text-slate-400">
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        <div className="grid gap-10 sm:grid-cols-2 lg:grid-cols-[2fr_1fr_1fr_1fr_1fr]">
          {/* Brand */}
          <div>
            <Link href="/" className="flex items-center gap-2.5">
              <Image
                src="/logo_no_bg.png"
                alt="Additi Logo"
                width={220}
                height={220}
              />
            </Link>
            <p className="mt-4 max-w-xs text-sm leading-relaxed">
              A smart micro-loan risk scoring platform that makes lending fair,
              fast, and transparent for everyone.
            </p>

            {/* Social icons */}
            <div className="mt-5 flex gap-3">
              {socialLinks.map(({ label, href, svg }) => (
                <a
                  key={label}
                  href={href}
                  aria-label={label}
                  className="flex h-8 w-8 items-center justify-center rounded-lg bg-white/10 text-slate-400 transition hover:bg-white/20 hover:text-white"
                >
                  {svg}
                </a>
              ))}
            </div>

            {/* Compliance badges */}
            <div className="mt-5 flex flex-wrap gap-2">
              {["SOC 2", "ISO 27001", "GDPR Ready"].map((badge) => (
                <span
                  key={badge}
                  className="rounded border border-white/10 bg-white/5 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-slate-500"
                >
                  {badge}
                </span>
              ))}
            </div>
          </div>

          {Object.entries(footerLinks).map(([group, links]) => (
            <div key={group}>
              <h4 className="mb-4 text-xs font-bold uppercase tracking-widest text-slate-500">
                {group}
              </h4>
              <ul className="space-y-2.5">
                {links.map(({ label, href }) => (
                  <li key={label}>
                    <Link
                      href={href}
                      className="text-sm transition hover:text-white"
                    >
                      {label}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        {/* Newsletter */}
        <div className="mt-12 rounded-2xl border border-white/10 bg-white/5 px-8 py-6">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-bold text-white">Stay in the loop</p>
              <p className="text-xs text-slate-400">
                Get product updates, industry insights, and credit tips
                delivered monthly.
              </p>
            </div>
            <div className="flex gap-2">
              <input
                type="email"
                placeholder="your@email.com"
                className="w-52 rounded-xl border border-white/10 bg-white/10 px-4 py-2 text-sm text-white placeholder-slate-500 outline-none transition focus:border-teal-400/50 focus:ring-2 focus:ring-teal-400/20"
              />
              <button className="rounded-xl bg-teal-500 px-5 py-2 text-sm font-bold text-white transition hover:bg-teal-400">
                Subscribe
              </button>
            </div>
          </div>
        </div>

        <div className="mt-10 flex flex-col items-center justify-center gap-4 border-t border-white/10 pt-7 sm:flex-row">
          <p className="text-xs">
            © 2026 Additi Technologies, Inc. All rights reserved.
          </p>
        </div>
      </div>
    </footer>
  );
}
