import { Navigation } from "@/components/Navigation";
import { MalwareAnalyzer } from "@/components/MalwareAnalyzer";

export default function AnalyzerPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navigation currentPage="DeepScan Analyzer" variant="bar" enableHomeHotkey />
      <main className="pt-20 px-4 md:px-6 pb-6 max-w-5xl mx-auto">
        <MalwareAnalyzer />
      </main>
    </div>
  );
}
