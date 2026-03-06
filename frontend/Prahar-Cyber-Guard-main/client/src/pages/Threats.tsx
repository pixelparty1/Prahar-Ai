import { Navigation } from "@/components/Navigation";
import { ThreatIntel } from "@/components/ThreatIntel";

export default function ThreatsPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navigation currentPage="Threat Intelligence" variant="bar" enableHomeHotkey />
      <main className="pt-20 px-4 md:px-6 pb-6 max-w-5xl mx-auto">
        <ThreatIntel />
      </main>
    </div>
  );
}
