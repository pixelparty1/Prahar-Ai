import { Navigation } from "@/components/Navigation";

type BotDetails = {
  name: string;
  summary: string;
  capabilities: string[];
};

const bots: BotDetails[] = [
  {
    name: "ContentMaster AI",
    summary:
      "Generates viral-ready content, captions, and hooks tailored to your brand voice, with trend-aware publishing logic.",
    capabilities: [
      "30+ weekly post generation",
      "Real-time trend and hashtag analysis",
      "Auto scheduling at peak engagement windows",
    ],
  },
  {
    name: "AdGenius AI",
    summary:
      "Monitors and optimizes paid campaigns in real time by shifting budgets, refining targeting, and scaling top performers.",
    capabilities: [
      "Continuous budget reallocation",
      "Automated A/B creative and audience testing",
      "Smart bidding to improve CPA and ROI",
    ],
  },
  {
    name: "EngageBot AI",
    summary:
      "Responds instantly to comments and DMs, qualifies leads in chat, and keeps your audience engaged around the clock.",
    capabilities: [
      "24/7 response automation",
      "Lead qualification via conversational flows",
      "Follow-up sequences with CRM handoff",
    ],
  },
  {
    name: "InsightIQ AI",
    summary:
      "Transforms campaign, audience, and competitor data into clear, action-ready insights and strategic recommendations.",
    capabilities: [
      "Predictive performance forecasting",
      "Competitor and trend intelligence",
      "Automated reporting and KPI dashboards",
    ],
  },
  {
    name: "VideoForge AI",
    summary:
      "Creates high-volume short-form videos optimized for Reels, TikTok, and Shorts using trend-native creative logic.",
    capabilities: [
      "Auto-generated hooks and captions",
      "Platform-specific format optimization",
      "Fast production for weekly content velocity",
    ],
  },
];

export default function AboutPage() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navigation currentPage="About PRAHAAR" variant="bar" enableHomeHotkey />
      <main className="pt-20 px-6 max-w-4xl mx-auto">
        <div className="glass-panel rounded-lg p-6 border border-white/10">
          <h1 className="font-display text-3xl text-glow">About PRAHAAR</h1>
          <p className="mt-4 text-muted-foreground leading-relaxed">
            PRAHAAR is an autonomous Red Team vs Blue Team AI cybersecurity simulation system built for live tactical demos,
            analyst training, and threat-response storytelling.
          </p>
        </div>

        <section className="mt-8 pb-14">
          <div className="glass-panel rounded-lg p-6 border border-white/10">
            <h2 className="font-display text-2xl text-foreground">AI Bot Architecture</h2>
            <p className="mt-3 text-muted-foreground">
              Detailed capabilities of all five PRAHAAR AI bots powering content, ads, engagement, analytics, and video operations.
            </p>
          </div>

          <div className="mt-6 grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-5">
            {bots.map((bot) => (
              <article
                key={bot.name}
                className="relative overflow-hidden rounded-xl border border-primary/20 bg-card/75 p-6 shadow-[0_10px_40px_rgba(0,0,0,0.35),0_0_28px_hsl(var(--primary)/0.22),0_0_54px_hsl(var(--primary)/0.12)]"
              >
                {/* Ambient glow layer behind card content */}
                <div
                  aria-hidden="true"
                  className="pointer-events-none absolute -right-10 top-1/2 h-40 w-40 -translate-y-1/2 rounded-full bg-primary/25 blur-3xl"
                />

                <div className="relative z-10">
                  <h3 className="font-display text-xl text-foreground">{bot.name}</h3>

                  <p className="mt-3 text-muted-foreground leading-relaxed">{bot.summary}</p>

                  <ul className="mt-4 space-y-2 text-sm text-foreground/90">
                    {bot.capabilities.map((capability) => (
                      <li key={capability} className="flex items-start gap-2">
                        <span className="mt-0.5 text-primary">•</span>
                        <span>{capability}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </article>
            ))}
          </div>
        </section>
      </main>
    </div>
  );
}
