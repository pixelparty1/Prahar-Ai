import { useEffect, useState } from "react";
import { Link, useLocation } from "wouter";
import { ArrowLeft, ChevronRight, Home } from "lucide-react";
import { ThemeSwitcher } from "./ThemeSwitcher";

interface NavigationProps {
  currentPage?: string;
  showLogo?: boolean;
  variant?: "bar" | "button" | "breadcrumb";
  enableHomeHotkey?: boolean;
}

export function Navigation({
  currentPage,
  showLogo = true,
  variant = "bar",
  enableHomeHotkey = false,
}: NavigationProps) {
  const [location, navigate] = useLocation();
  const isHome = location === "/";
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    if (!enableHomeHotkey) {
      return;
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" || event.key === "h" || event.key === "H") {
        if (location !== "/") {
          navigate("/");
        }
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [enableHomeHotkey, location, navigate]);

  if (variant === "button") {
    return (
      <Link
        href="/"
        className="fixed top-6 left-6 z-50 flex items-center gap-2 px-4 py-2 bg-primary/10 hover:bg-primary/20 border border-primary/30 rounded-lg text-primary hover:text-primary transition backdrop-blur-sm font-mono"
      >
        <ArrowLeft className="w-4 h-4" />
        <span>Back to Home</span>
      </Link>
    );
  }

  if (variant === "breadcrumb") {
    return (
      <div className="fixed top-6 left-6 z-50 flex items-center gap-2 text-sm font-mono">
        <Link href="/" className="text-primary hover:text-primary/80 transition flex items-center gap-1">
          <Home className="w-4 h-4" />
          <span>Home</span>
        </Link>
        <ChevronRight className="w-4 h-4 text-muted-foreground" />
        <span className="text-muted-foreground">{currentPage || "Page"}</span>
      </div>
    );
  }

  return (
    <nav
      className={`fixed left-0 right-0 z-50 transition-all duration-500 ease-in-out top-0 translate-y-[calc(-100%+14px)] hover:translate-y-0 focus-within:translate-y-0 opacity-90 hover:opacity-100 focus-within:opacity-100 ${
        scrolled
          ? "bg-background/80 backdrop-blur-md border-b border-primary/20 shadow-lg shadow-black/10"
          : "bg-background/60 backdrop-blur-sm border-b border-transparent"
      }`}
    >
      <div className="max-w-7xl mx-auto px-4 md:px-6 py-3 flex items-center justify-between gap-4 navigation-bar">
        <Link href="/" className="flex items-center gap-3 hover:opacity-80 transition">
          {showLogo ? <img src="/logo.jpeg" alt="Prahaar" className="h-7 w-7 rounded-sm object-contain" /> : null}
          <span className="text-xl font-display font-bold text-white">PRAHAAR</span>
        </Link>

        <div className="hidden md:flex items-center gap-6 text-xs font-mono uppercase tracking-wider page-title">
          <Link href="/" className="text-muted-foreground hover:text-primary transition-colors duration-200">
            Home
          </Link>
          <Link
            href="/command-center"
            className="text-muted-foreground hover:text-primary transition-colors duration-200"
          >
            View Schematics
          </Link>
          <Link
            href="/about"
            className="text-muted-foreground hover:text-primary transition-colors duration-200"
          >
            About
          </Link>
          <Link
            href="/pricing"
            className="text-muted-foreground hover:text-primary transition-colors duration-200"
          >
            Pricing
          </Link>
        </div>

        <div className="flex items-center gap-2">
          <ThemeSwitcher />
        </div>
      </div>
    </nav>
  );
}
