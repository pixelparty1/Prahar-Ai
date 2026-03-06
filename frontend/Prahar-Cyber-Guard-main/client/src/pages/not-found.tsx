import { Link } from "wouter";
import { AlertTriangle, Home } from "lucide-react";
import { Navigation } from "@/components/Navigation";

export default function NotFound() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navigation currentPage="404 - Not Found" variant="bar" enableHomeHotkey />
      <div className="pt-20 min-h-screen flex items-center justify-center px-6">
        <div className="text-center glass-panel border border-white/10 rounded-lg p-8 max-w-lg w-full">
          <AlertTriangle className="w-16 h-16 text-destructive mx-auto mb-4" />
          <h1 className="text-5xl font-display font-bold text-white mb-2">404</h1>
          <p className="text-muted-foreground mb-6">Page not found in PRAHAAR system</p>

          <Link
            href="/"
            className="inline-flex items-center gap-2 px-6 py-3 bg-primary/20 hover:bg-primary/30 border border-primary/40 text-primary rounded-lg transition font-mono"
          >
            <Home className="w-5 h-5" />
            Return to Home Base
          </Link>
        </div>
      </div>
    </div>
  );
}
