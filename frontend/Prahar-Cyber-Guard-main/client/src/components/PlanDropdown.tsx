import { useEffect, useState } from "react";
import { useLocation } from "wouter";
import { ChevronDown, Crown, Shield, Zap, Building2, ArrowUpRight, ArrowDownRight } from "lucide-react";
import { PLANS, getPlanByTier, type PlanConfig } from "@/lib/plans";

export function PlanDropdown() {
  const [, navigate] = useLocation();
  const [open, setOpen] = useState(false);
  const [currentPlan, setCurrentPlan] = useState<PlanConfig | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchUserPlan() {
      const userId = localStorage.getItem("prahaar_user_id");
      if (!userId) {
        const stored = localStorage.getItem("prahaar_plan") || "free";
        setCurrentPlan(getPlanByTier(stored) || PLANS[0]);
        setLoading(false);
        return;
      }

      try {
        const res = await fetch(`/api/auth/user/${encodeURIComponent(userId)}`);
        if (res.ok) {
          const data = await res.json();
          const plan = getPlanByTier(data.plans || "free") || PLANS[0];
          setCurrentPlan(plan);
          localStorage.setItem("prahaar_plan", plan.tier);
        } else {
          const stored = localStorage.getItem("prahaar_plan") || "free";
          setCurrentPlan(getPlanByTier(stored) || PLANS[0]);
        }
      } catch {
        const stored = localStorage.getItem("prahaar_plan") || "free";
        setCurrentPlan(getPlanByTier(stored) || PLANS[0]);
      } finally {
        setLoading(false);
      }
    }

    fetchUserPlan();
  }, []);

  const handlePlanAction = (tier: string) => {
    localStorage.setItem("prahaar_plan", tier);
    setOpen(false);
    navigate("/transaction");
  };

  const tierIcon = (tier: string) => {
    switch (tier) {
      case "free": return <Shield className="w-4 h-4" />;
      case "starter": return <Zap className="w-4 h-4" />;
      case "pro": return <Crown className="w-4 h-4" />;
      case "enterprise": return <Building2 className="w-4 h-4" />;
      default: return <Shield className="w-4 h-4" />;
    }
  };

  const tierIndex = currentPlan ? PLANS.findIndex((p) => p.tier === currentPlan.tier) : 0;

  if (loading) return null;

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 rounded-md border border-border bg-card/60 px-3 py-2 text-sm font-mono text-foreground transition-colors hover:bg-card/80"
      >
        {tierIcon(currentPlan?.tier || "free")}
        <span className="hidden sm:inline">My Plan</span>
        <span className="text-primary font-semibold">{currentPlan?.name || "Free"}</span>
        <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open && (
        <>
          {/* Backdrop */}
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />

          {/* Dropdown */}
          <div className="absolute right-0 top-full mt-2 z-50 w-80 rounded-lg border border-border bg-card shadow-[0_20px_60px_rgba(0,0,0,0.5)] overflow-hidden">
            {/* Current plan header */}
            <div className="p-4 border-b border-border bg-primary/5">
              <div className="flex items-center gap-2 mb-1">
                {tierIcon(currentPlan?.tier || "free")}
                <span className="font-display text-base text-foreground">{currentPlan?.name}</span>
              </div>
              <p className="text-lg font-bold text-primary font-display">{currentPlan?.price}</p>
              <p className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mt-1">Current Plan</p>
            </div>

            {/* Benefits */}
            <div className="p-3 border-b border-border">
              <p className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Plan Benefits</p>
              <ul className="space-y-1.5">
                {currentPlan?.benefits.map((b) => (
                  <li key={b} className="flex items-start gap-2 text-xs text-foreground/80">
                    <span className="text-primary mt-0.5">•</span>
                    <span>{b}</span>
                  </li>
                ))}
              </ul>
            </div>

            {/* Upgrade/Downgrade options */}
            <div className="p-3">
              <p className="text-[11px] font-mono uppercase tracking-wider text-muted-foreground mb-2">Change Plan</p>
              <div className="space-y-1.5">
                {PLANS.map((p, idx) => {
                  if (p.tier === currentPlan?.tier) return null;
                  const isUpgrade = idx > tierIndex;
                  return (
                    <button
                      key={p.tier}
                      type="button"
                      onClick={() => handlePlanAction(p.tier)}
                      className="flex items-center justify-between w-full rounded-md px-3 py-2 text-sm text-foreground transition-colors hover:bg-primary/10"
                    >
                      <div className="flex items-center gap-2">
                        {tierIcon(p.tier)}
                        <span>{isUpgrade ? "Upgrade to" : "Downgrade to"} {p.name}</span>
                      </div>
                      <div className="flex items-center gap-1 text-xs text-muted-foreground">
                        <span>{p.price}</span>
                        {isUpgrade ? (
                          <ArrowUpRight className="w-3.5 h-3.5 text-green-400" />
                        ) : (
                          <ArrowDownRight className="w-3.5 h-3.5 text-yellow-400" />
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
