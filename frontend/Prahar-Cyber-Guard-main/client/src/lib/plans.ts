export interface PlanConfig {
  name: string;
  tier: "free" | "starter" | "pro" | "enterprise";
  price: string;
  priceNum: number;
  benefits: string[];
}

export const PLANS: PlanConfig[] = [
  {
    name: "Free Tier",
    tier: "free",
    price: "Free",
    priceNum: 0,
    benefits: [
      "Basic vulnerability scan",
      "1 website limit",
      "Monthly security report",
      "Community support",
    ],
  },
  {
    name: "Starter",
    tier: "starter",
    price: "₹999/month",
    priceNum: 999,
    benefits: [
      "Full attack simulation",
      "Weekly vulnerability scans",
      "Basic security dashboard",
      "Email alerts",
    ],
  },
  {
    name: "Pro",
    tier: "pro",
    price: "₹4,999/month",
    priceNum: 4999,
    benefits: [
      "AttackBot + DefendBot + NarratorBot",
      "Real-time security defense",
      "24/7 monitoring",
      "Unlimited vulnerability scans",
      "Security alerts",
    ],
  },
  {
    name: "Enterprise",
    tier: "enterprise",
    price: "Custom Pricing",
    priceNum: 0,
    benefits: [
      "Dedicated security support",
      "API access",
      "Compliance reporting",
      "White-label security platform",
      "Custom integrations",
    ],
  },
];

export function getPlanByTier(tier: string): PlanConfig | undefined {
  return PLANS.find((p) => p.tier === tier);
}
