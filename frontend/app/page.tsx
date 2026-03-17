import LandingNavbar from "../components/landing/LandingNavbar";
import HeroSection from "../components/landing/HeroSection";
import HowItWorksSection from "../components/landing/HowItWorksSection";
import ContactSection from "../components/landing/ContactSection";
import LandingFooter from "../components/landing/LandingFooter";

export default function Home() {
  return (
    <>
      <LandingNavbar />
      <HeroSection />
      <HowItWorksSection />
      <ContactSection />
      <LandingFooter />
    </>
  );
}
