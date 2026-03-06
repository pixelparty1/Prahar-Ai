import { useState, type FormEvent } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import { Navigation } from "@/components/Navigation";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { Check, CreditCard, Loader2, ShieldCheck, ArrowLeft } from "lucide-react";
import { getPlanByTier, type PlanConfig } from "@/lib/plans";

type TxStage = "form" | "processing" | "success" | "error";

export default function TransactionPage() {
  const [, navigate] = useLocation();

  const tier = typeof window !== "undefined" ? localStorage.getItem("prahaar_plan") || "free" : "free";
  const plan: PlanConfig = getPlanByTier(tier) || getPlanByTier("free")!;

  const [stage, setStage] = useState<TxStage>("form");
  const [cardNumber, setCardNumber] = useState("");
  const [expiry, setExpiry] = useState("");
  const [cvv, setCvv] = useState("");
  const [errorMsg, setErrorMsg] = useState("");

  const formatCardNumber = (val: string) => {
    const digits = val.replace(/\D/g, "").slice(0, 16);
    return digits.replace(/(.{4})/g, "$1 ").trim();
  };

  const formatExpiry = (val: string) => {
    const digits = val.replace(/\D/g, "").slice(0, 4);
    if (digits.length >= 3) return digits.slice(0, 2) + "/" + digits.slice(2);
    return digits;
  };

  async function handleConfirm(e: FormEvent) {
    e.preventDefault();
    setErrorMsg("");

    if (cardNumber.replace(/\s/g, "").length < 16) {
      setErrorMsg("Please enter a valid 16-digit card number.");
      return;
    }
    if (expiry.length < 5) {
      setErrorMsg("Please enter a valid expiry date (MM/YY).");
      return;
    }
    if (cvv.length < 3) {
      setErrorMsg("Please enter a valid CVV.");
      return;
    }

    setStage("processing");

    // Simulate processing delay
    await new Promise((r) => setTimeout(r, 2200));

    const userId = localStorage.getItem("prahaar_user_id");
    if (!userId) {
      setStage("error");
      setErrorMsg("You must be logged in to subscribe. Please sign in first.");
      return;
    }

    try {
      const res = await fetch("/api/auth/update-plan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userId, selectedPlan: plan.tier }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Plan update failed.");
      localStorage.setItem("prahaar_plan", plan.tier);
      setStage("success");
      setTimeout(() => navigate("/command-center"), 1800);
    } catch (err: any) {
      setStage("error");
      setErrorMsg(err?.message || "Transaction failed. Please try again.");
    }
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navigation currentPage="Transaction" variant="bar" enableHomeHotkey />

      <main className="relative z-10 pt-24 px-4 md:px-6 pb-20 max-w-2xl mx-auto">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
          {/* Back button */}
          <button
            type="button"
            onClick={() => navigate("/pricing")}
            className="flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground transition-colors mb-6"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Plans
          </button>

          {/* Plan summary */}
          <Card className="border-primary/30 bg-card/75 mb-6">
            <CardHeader className="pb-3">
              <CardTitle className="font-display text-xl">Confirm Your Subscription</CardTitle>
              <CardDescription>
                You are subscribing to the <span className="text-primary font-semibold">{plan.name}</span> — <span className="font-semibold">{plan.price}</span>
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2">
                {plan.benefits.map((b) => (
                  <li key={b} className="flex items-start gap-2 text-sm text-foreground/90">
                    <Check className="w-4 h-4 mt-0.5 text-primary shrink-0" />
                    <span>{b}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>

          {/* Payment form / states */}
          {stage === "form" && (
            <Card className="border-border bg-card/75">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <CreditCard className="w-5 h-5 text-primary" />
                  <CardTitle className="font-display text-lg">Payment Details</CardTitle>
                </div>
                <CardDescription className="text-xs text-muted-foreground">
                  This is a simulated payment. No real charges will be made.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleConfirm} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="card-number" className="font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground">
                      Card Number
                    </Label>
                    <Input
                      id="card-number"
                      placeholder="1234 5678 9012 3456"
                      value={cardNumber}
                      onChange={(e) => setCardNumber(formatCardNumber(e.target.value))}
                      className="h-11 border-white/10 bg-background/70 font-mono text-sm text-foreground placeholder:text-muted-foreground/70"
                      maxLength={19}
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="card-expiry" className="font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground">
                        Expiry Date
                      </Label>
                      <Input
                        id="card-expiry"
                        placeholder="MM/YY"
                        value={expiry}
                        onChange={(e) => setExpiry(formatExpiry(e.target.value))}
                        className="h-11 border-white/10 bg-background/70 font-mono text-sm text-foreground placeholder:text-muted-foreground/70"
                        maxLength={5}
                      />
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="card-cvv" className="font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground">
                        CVV
                      </Label>
                      <Input
                        id="card-cvv"
                        placeholder="123"
                        value={cvv}
                        onChange={(e) => setCvv(e.target.value.replace(/\D/g, "").slice(0, 4))}
                        className="h-11 border-white/10 bg-background/70 font-mono text-sm text-foreground placeholder:text-muted-foreground/70"
                        maxLength={4}
                      />
                    </div>
                  </div>

                  {errorMsg && <p className="text-xs font-mono text-red-400">{errorMsg}</p>}

                  <div className="flex gap-3 pt-2">
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => navigate("/pricing")}
                      className="flex-1 h-11 rounded-none font-mono text-xs uppercase tracking-[0.28em]"
                    >
                      Cancel
                    </Button>
                    <Button
                      type="submit"
                      className="flex-1 h-11 rounded-none font-mono text-xs uppercase tracking-[0.28em]"
                    >
                      Confirm Payment
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          )}

          {stage === "processing" && (
            <Card className="border-primary/30 bg-card/75">
              <CardContent className="flex flex-col items-center justify-center py-16 gap-4">
                <Loader2 className="w-10 h-10 text-primary animate-spin" />
                <p className="font-mono text-sm text-muted-foreground">Processing your payment…</p>
                <div className="w-48 h-1 rounded-full bg-primary/20 overflow-hidden">
                  <motion.div
                    className="h-full bg-primary rounded-full"
                    initial={{ width: "0%" }}
                    animate={{ width: "100%" }}
                    transition={{ duration: 2, ease: "easeInOut" }}
                  />
                </div>
              </CardContent>
            </Card>
          )}

          {stage === "success" && (
            <Card className="border-green-700/50 bg-green-950/20">
              <CardContent className="flex flex-col items-center justify-center py-16 gap-4">
                <div className="flex items-center justify-center w-14 h-14 rounded-full bg-green-500/20 border border-green-500/40">
                  <ShieldCheck className="w-7 h-7 text-green-400" />
                </div>
                <p className="font-display text-xl text-green-400">Payment Successful!</p>
                <p className="text-sm text-muted-foreground">
                  You are now on the <span className="text-primary font-semibold">{plan.name}</span>. Redirecting to dashboard…
                </p>
              </CardContent>
            </Card>
          )}

          {stage === "error" && (
            <Card className="border-red-700/50 bg-red-950/20">
              <CardContent className="flex flex-col items-center justify-center py-12 gap-4">
                <p className="font-display text-xl text-red-400">Transaction Failed</p>
                <p className="text-sm text-muted-foreground text-center">{errorMsg}</p>
                <div className="flex gap-3">
                  <Button variant="outline" onClick={() => navigate("/auth")} className="rounded-none font-mono text-xs uppercase tracking-[0.28em]">
                    Sign In
                  </Button>
                  <Button onClick={() => setStage("form")} className="rounded-none font-mono text-xs uppercase tracking-[0.28em]">
                    Try Again
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}
        </motion.div>
      </main>
    </div>
  );
}
