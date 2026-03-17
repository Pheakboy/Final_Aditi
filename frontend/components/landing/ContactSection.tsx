"use client";

import { useState } from "react";
import { Mail, Phone, MapPin, ArrowRight, CheckCircle } from "lucide-react";

const inquiryTypes = [
  "General Inquiry",
  "Loan Application Help",
  "Institutional Partnership",
  "Technical Support",
  "Press & Media",
  "Other",
];

type FormState = { name: string; email: string; type: string; message: string };

export default function ContactSection() {
  const [form, setForm] = useState<FormState>({
    name: "",
    email: "",
    type: "",
    message: "",
  });
  const [errors, setErrors] = useState<Partial<FormState>>({});
  const [submitted, setSubmitted] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const validate = (): Partial<FormState> => {
    const e: Partial<FormState> = {};
    if (!form.name.trim()) e.name = "Full name is required";
    if (!form.email.trim()) e.email = "Email address is required";
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email))
      e.email = "Enter a valid email address";
    if (!form.type) e.type = "Please select an inquiry type";
    if (!form.message.trim()) e.message = "Message is required";
    else if (form.message.trim().length < 20)
      e.message = "Message must be at least 20 characters";
    return e;
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const errs = validate();
    if (Object.keys(errs).length > 0) {
      setErrors(errs);
      return;
    }
    setSubmitting(true);
    setTimeout(() => {
      setSubmitting(false);
      setSubmitted(true);
    }, 1200);
  };

  const inputClass = (field: keyof FormState) =>
    `w-full rounded-xl border px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 outline-none transition focus:ring-2 focus:ring-teal-400/30 ${
      errors[field]
        ? "border-rose-400 bg-rose-50"
        : "border-slate-200 bg-white focus:border-teal-400"
    }`;

  return (
    <section id="contact" className="bg-white py-24">
      <div className="mx-auto max-w-7xl px-6 lg:px-10">
        {/* Heading */}
        <div className="mb-14 text-center">
          <span className="inline-flex rounded-full border border-teal-200 bg-teal-50 px-3 py-1 text-xs font-bold uppercase tracking-[0.14em] text-teal-700">
            Get in Touch
          </span>
          <h2 className="mt-4 text-4xl font-black text-slate-900">
            We&apos;d love to hear from you.
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-base text-slate-500">
            Whether you&apos;re a borrower with questions or an institution
            looking to partner, our team responds within 24 hours.
          </p>
        </div>

        <div className="grid gap-12 lg:grid-cols-[1fr_1.6fr]">
          {/* Left – contact info */}
          <div className="space-y-8">
            <div>
              <h3 className="mb-5 text-lg font-bold text-slate-900">
                Contact Information
              </h3>
              <div className="space-y-4">
                {[
                  {
                    icon: <Mail size={18} />,
                    label: "Email",
                    value: "SmartLoansupport@gmail.com",
                    href: "mailto:SmartLoansupport@gmail.com",
                  },
                  {
                    icon: <Phone size={18} />,
                    label: "Phone",
                    value: "+855 969-620-934",
                    href: "tel:+855969620934",
                  },
                  {
                    icon: <MapPin size={18} />,
                    label: "Address",
                    value:
                      "123 Main Street\nPhnom Penh, Cambodia",
                    href: null,
                  },
                ].map(({ icon, label, value, href }) => (
                  <div key={label} className="flex items-start gap-3">
                    <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-600">
                      {icon}
                    </div>
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                        {label}
                      </p>
                      {href ? (
                        <a
                          href={href}
                          className="text-sm font-medium text-slate-700 transition hover:text-teal-600"
                        >
                          {value}
                        </a>
                      ) : (
                        <p className="whitespace-pre-line text-sm font-medium text-slate-700">
                          {value}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Business hours */}
            <div className="rounded-2xl border border-slate-100 bg-slate-50 p-5">
              <h4 className="mb-3 text-sm font-bold text-slate-700">
                Business Hours
              </h4>
              <div className="space-y-1.5 text-sm">
                {[
                  { day: "Monday – Friday", hours: "9 AM – 6 PM " },
                  { day: "Saturday", hours: "10 AM – 2 PM" },
                  { day: "Sunday", hours: "Closed" },
                ].map(({ day, hours }) => (
                  <div key={day} className="flex justify-between">
                    <span className="text-slate-500">{day}</span>
                    <span className="font-semibold text-slate-700">
                      {hours}
                    </span>
                  </div>
                ))}
              </div>
              <p className="mt-3 text-xs text-slate-400">
                Platform support is available 24/7 through the help center.
              </p>
            </div>
          </div>

          {/* Right – form */}
          <div className="glass card-shadow rounded-2xl p-8">
            {submitted ? (
              <div className="flex flex-col items-center justify-center py-16 text-center">
                <div className="mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-emerald-100">
                  <CheckCircle size={32} className="text-emerald-600" />
                </div>
                <h3 className="text-xl font-bold text-slate-900">
                  Message Sent!
                </h3>
                <p className="mt-2 max-w-xs text-sm text-slate-500">
                  Thank you for reaching out. Our team will get back to you
                  within 24 hours.
                </p>
                <button
                  onClick={() => {
                    setSubmitted(false);
                    setForm({ name: "", email: "", type: "", message: "" });
                    setErrors({});
                  }}
                  className="mt-6 text-sm font-semibold text-teal-600 hover:text-teal-700"
                >
                  Send another message
                </button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-5" noValidate>
                <h3 className="text-lg font-bold text-slate-900">
                  Send us a message
                </h3>

                <div className="grid gap-5 sm:grid-cols-2">
                  <div>
                    <label
                      htmlFor="contact-name"
                      className="mb-1.5 block text-xs font-semibold text-slate-600"
                    >
                      Full Name
                    </label>
                    <input
                      id="contact-name"
                      type="text"
                      placeholder="Jane Smith"
                      value={form.name}
                      onChange={(e) => {
                        setForm({ ...form, name: e.target.value });
                        setErrors({ ...errors, name: "" });
                      }}
                      className={inputClass("name")}
                    />
                    {errors.name && (
                      <p className="mt-1 text-xs text-rose-500">
                        {errors.name}
                      </p>
                    )}
                  </div>
                  <div>
                    <label
                      htmlFor="contact-email"
                      className="mb-1.5 block text-xs font-semibold text-slate-600"
                    >
                      Email Address
                    </label>
                    <input
                      id="contact-email"
                      type="email"
                      placeholder="jane@example.com"
                      value={form.email}
                      onChange={(e) => {
                        setForm({ ...form, email: e.target.value });
                        setErrors({ ...errors, email: "" });
                      }}
                      className={inputClass("email")}
                    />
                    {errors.email && (
                      <p className="mt-1 text-xs text-rose-500">
                        {errors.email}
                      </p>
                    )}
                  </div>
                </div>

                <div>
                  <label
                    htmlFor="contact-type"
                    className="mb-1.5 block text-xs font-semibold text-slate-600"
                  >
                    Inquiry Type
                  </label>
                  <select
                    id="contact-type"
                    value={form.type}
                    onChange={(e) => {
                      setForm({ ...form, type: e.target.value });
                      setErrors({ ...errors, type: "" });
                    }}
                    className={inputClass("type")}
                  >
                    <option value="">Select an inquiry type…</option>
                    {inquiryTypes.map((t) => (
                      <option key={t} value={t}>
                        {t}
                      </option>
                    ))}
                  </select>
                  {errors.type && (
                    <p className="mt-1 text-xs text-rose-500">{errors.type}</p>
                  )}
                </div>

                <div>
                  <label
                    htmlFor="contact-message"
                    className="mb-1.5 block text-xs font-semibold text-slate-600"
                  >
                    Message
                  </label>
                  <textarea
                    id="contact-message"
                    rows={5}
                    placeholder="Tell us how we can help you…"
                    value={form.message}
                    onChange={(e) => {
                      setForm({ ...form, message: e.target.value });
                      setErrors({ ...errors, message: "" });
                    }}
                    className={`resize-none ${inputClass("message")}`}
                  />
                  {errors.message && (
                    <p className="mt-1 text-xs text-rose-500">
                      {errors.message}
                    </p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={submitting}
                  className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-slate-900 px-6 py-3.5 text-sm font-bold text-white transition hover:-translate-y-0.5 hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {submitting ? (
                    <>
                      <span className="h-4 w-4 animate-spin rounded-full border-2 border-white/30 border-t-white" />
                      Sending…
                    </>
                  ) : (
                    <>
                      Send Message <ArrowRight size={16} />
                    </>
                  )}
                </button>

                <p className="text-center text-xs text-slate-400">
                  By submitting, you agree to our{" "}
                  <a href="#" className="underline hover:text-slate-600">
                    Privacy Policy
                  </a>
                  .
                </p>
              </form>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
