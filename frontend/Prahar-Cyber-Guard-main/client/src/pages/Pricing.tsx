import { motion } from "framer-motion";
import { useLocation } from "wouter";
import { Navigation } from "@/components/Navigation";
import { Shield, Zap, Crown, Building2, Check } from "lucide-react";

interface Plan {
  name: string;
  price: string;
  description: string;
  features: string[];
  cta: string;
  icon: React.ReactNode;
  popular?: boolean;
  tier: "free" | "starter" | "pro" | "enterprise";
}

const plans: Plan[] = [
  {
    name: "Free Tier",
    price: "Free",
    description:
      "Basic vulnerability scan, limited to 1 website, monthly report only.",
    features: [
      "Basic vulnerability scan",
      "1 website limit",
      "Monthly security report",
      "Community support",
    ],
    cta: "Get Started Free",
    icon: <Shield className="w-6 h-6" />,
    tier: "free",
  },
  {
    name: "Starter",
    price: "₹999/month",
    description:
      "Full attack simulation with weekly scans and a basic security dashboard.",
    features: [
      "Full attack simulation",
      "Weekly vulnerability scans",
      "Basic security dashboard",
      "Email alerts",
    ],
    cta: "Start Starter Plan",
    icon: <Zap className="w-6 h-6" />,
    tier: "starter",
  },
  {
    name: "Pro",
    price: "₹4,999/month",
    description:
      "All security agents active with real-time defense and continuous monitoring.",
    features: [
      "AttackBot + DefendBot + NarratorBot",
      "Real-time security defense",
      "24/7 monitoring",
      "Unlimited vulnerability scans",
      "Security alerts",
    ],
    cta: "Upgrade to Pro",
    icon: <Crown className="w-6 h-6" />,
    popular: true,
    tier: "pro",
  },
  {
    name: "Enterprise",
    price: "Custom Pricing",
    description:
      "Enterprise-grade security with dedicated support and compliance reporting.",
    features: [
      "Dedicated security support",
      "API access",
      "Compliance reporting",
      "White-label security platform",
      "Custom integrations",
    ],
    cta: "Contact Sales",
    icon: <Building2 className="w-6 h-6" />,
    tier: "enterprise",
  },
];

const cardVariants = {
  hidden: { opacity: 0, y: 30 },
  visible: (i: number) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.5, delay: i * 0.12, ease: "easeOut" },
  }),
};

export default function PricingPage() {
  const [, navigate] = useLocation();

  const handlePlanSelect = (plan: Plan) => {
    localStorage.setItem("prahaar_plan", plan.tier);
    navigate("/command-center");
  };

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navigation
        currentPage="Pricing & Plans"
        variant="bar"
        enableHomeHotkey
      />

      <main className="pt-24 px-4 md:px-6 pb-20 max-w-7xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6, ease: "easeOut" }}
          className="text-center mb-16"
        >
          <h1 className="font-display text-4xl md:text-5xl font-bold tracking-tight text-foreground">
            Security Plans
          </h1>
          <p className="mt-4 max-w-xl mx-auto text-muted-foreground leading-relaxed">
            Choose the plan that fits your security needs. Start free and scale
            as your website grows.
          </p>
        </motion.div>

        {/* Pricing Cards Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-6">
          {plans.map((plan, i) => (
            <motion.div
              key={plan.name}
              custom={i}
              initial="hidden"
              animate="visible"
              variants={cardVariants}
              className={`group relative flex flex-col overflow-hidden rounded-xl border bg-card/75 p-6 transition-all duration-300 hover:-translate-y-1 hover:shadow-[0_12px_40px_rgba(0,0,0,0.4),0_0_24px_hsl(var(--primary)/0.15)] ${
                plan.popular
                  ? "border-primary/50 shadow-[0_0_20px_hsl(var(--primary)/0.12)]"
                  : "border-primary/20"
              }`}
            >
              {/* Ambient glow */}
              <div
                aria-hidden="true"
                className="pointer-events-none absolute -right-10 top-1/2 h-36 w-36 -translate-y-1/2 rounded-full bg-primary/15 blur-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-500"
              />

              {/* Most Popular Badge */}
              {plan.popular && (
                <span className="absolute top-4 right-4 px-2.5 py-0.5 rounded-md bg-primary text-primary-foreground text-[10px] font-mono font-semibold uppercase tracking-wider">
                  Most Popular
                </span>
              )}

              {/* Icon */}
              <div className="relative z-10 flex items-center justify-center w-10 h-10 rounded-lg bg-primary/10 border border-primary/20 text-primary mb-5">
                {plan.icon}
              </div>

              {/* Plan Name */}
              <h2 className="relative z-10 font-display text-xl text-foreground">
                {plan.name}
              </h2>

              {/* Price */}
              <p className="relative z-10 mt-2 font-display text-3xl font-bold text-foreground tracking-tight">
                {plan.price}
              </p>

              {/* Description */}
              <p className="relative z-10 mt-3 text-sm text-muted-foreground leading-relaxed">
                {plan.description}
              </p>

              {/* Features */}
              <ul className="relative z-10 mt-5 space-y-2.5 flex-1">
                {plan.features.map((feature) => (
                  <li
                    key={feature}
                    className="flex items-start gap-2.5 text-sm text-foreground/90"
                  >
                    <Check className="w-4 h-4 mt-0.5 text-primary shrink-0" />
                    <span>{feature}</span>
                  </li>
                ))}
              </ul>

              {/* CTA Button */}
              <button
                onClick={() => handlePlanSelect(plan)}
                className={`relative z-10 mt-6 w-full py-3 rounded-md font-mono text-sm font-semibold tracking-wider transition-colors duration-200 ${
                  plan.popular
                    ? "bg-primary text-primary-foreground hover:bg-primary/90"
                    : "bg-primary/10 text-primary border border-primary/30 hover:bg-primary/20"
                }`}
              >
                {plan.cta}
              </button>
            </motion.div>
          ))}
        </div>
      </main>
    </div>
  );
}
