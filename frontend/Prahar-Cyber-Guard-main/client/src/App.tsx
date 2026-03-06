import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { CursorGlow } from "@/components/CursorGlow";
import { ThemeProvider } from "@/contexts/ThemeContext";
import NotFound from "@/pages/not-found";
import Home from "@/pages/Home";
import CommandCenterPage from "@/pages/CommandCenter";
import AnalyzerPage from "@/pages/Analyzer";
import ThreatsPage from "@/pages/Threats";
import AboutPage from "@/pages/About";
import PricingPage from "@/pages/Pricing";
import AuthPage from "@/pages/Auth";
import ScanResultsPage from "@/pages/ScanResults";

function Router() {
  return (
    <Switch>
      <Route path="/" component={Home} />
      <Route path="/auth" component={AuthPage} />
      <Route path="/command-center" component={CommandCenterPage} />
      <Route path="/war-room" component={CommandCenterPage} />
      <Route path="/warroom" component={CommandCenterPage} />
      <Route path="/analyzer" component={AnalyzerPage} />
      <Route path="/threats" component={ThreatsPage} />
      <Route path="/about" component={AboutPage} />
      <Route path="/pricing" component={PricingPage} />
      <Route path="/scan/results/:scanId" component={ScanResultsPage} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider>
          <CursorGlow />
          <Toaster />
          <Router />
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
