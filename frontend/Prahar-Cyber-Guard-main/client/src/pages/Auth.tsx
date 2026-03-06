import { useState, type FormEvent } from "react";
import { useLocation } from "wouter";
import { ChevronRight, ShieldCheck, UserPlus, Loader2 } from "lucide-react";
import { Navigation } from "@/components/Navigation";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

/* ── Sign-In form ────────────────────────────────────── */
function SignInForm() {
  const [, navigate] = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ emailAddress: email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Invalid credentials.");
      navigate("/command-center");
    } catch (err: any) {
      setError(err?.message || "Sign-in failed. Check your credentials.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="border-white/10 bg-card/75 shadow-[0_18px_80px_rgba(0,0,0,0.45),0_0_36px_hsl(var(--primary)/0.16)] backdrop-blur-xl">
      <CardHeader>
        <CardTitle className="font-display text-2xl text-foreground">Operator Sign In</CardTitle>
        <CardDescription className="text-muted-foreground">Access an existing PRAHAAR operator session.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="signin-email" className="font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground">Operator Email</Label>
              <Input id="signin-email" type="email" placeholder="operator@prahaar.ai" value={email} onChange={(e) => setEmail(e.target.value)} className="h-11 border-white/10 bg-background/70 font-mono text-sm text-foreground placeholder:text-muted-foreground/70" required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="signin-password" className="font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground">Password</Label>
              <Input id="signin-password" type="password" placeholder="Enter secure passphrase" value={password} onChange={(e) => setPassword(e.target.value)} className="h-11 border-white/10 bg-background/70 font-mono text-sm text-foreground placeholder:text-muted-foreground/70" required />
            </div>
          </div>

          {error && <p className="text-xs font-mono text-red-400">{error}</p>}

          <Button type="submit" disabled={loading} className="h-11 w-full rounded-none font-mono text-xs uppercase tracking-[0.28em]">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <>Enter Command Center <ChevronRight className="h-4 w-4" /></>}
          </Button>

          <p className="text-center font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground/80">
            Secure access gateway for PRAHAAR operators
          </p>
        </form>
      </CardContent>
    </Card>
  );
}

/* ── Sign-Up form ────────────────────────────────────── */
function SignUpForm() {
  const [, navigate] = useLocation();
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const res = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ firstName: name, emailAddress: email, password }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Registration failed.");
      navigate("/command-center");
    } catch (err: any) {
      setError(err?.message || "Registration failed. Try a different email.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="border-white/10 bg-card/75 shadow-[0_18px_80px_rgba(0,0,0,0.45),0_0_36px_hsl(var(--primary)/0.16)] backdrop-blur-xl">
      <CardHeader>
        <CardTitle className="font-display text-2xl text-foreground">Create Operator Profile</CardTitle>
        <CardDescription className="text-muted-foreground">Register a new PRAHAAR access profile for simulation entry.</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="signup-name" className="font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground">Operator Name</Label>
              <Input id="signup-name" type="text" placeholder="Enter full operator name" value={name} onChange={(e) => setName(e.target.value)} className="h-11 border-white/10 bg-background/70 font-mono text-sm text-foreground placeholder:text-muted-foreground/70" required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="signup-email" className="font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground">Operator Email</Label>
              <Input id="signup-email" type="email" placeholder="new.operator@prahaar.ai" value={email} onChange={(e) => setEmail(e.target.value)} className="h-11 border-white/10 bg-background/70 font-mono text-sm text-foreground placeholder:text-muted-foreground/70" required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="signup-password" className="font-mono text-[11px] uppercase tracking-[0.28em] text-muted-foreground">Create Password</Label>
              <Input id="signup-password" type="password" placeholder="Set secure passphrase" value={password} onChange={(e) => setPassword(e.target.value)} className="h-11 border-white/10 bg-background/70 font-mono text-sm text-foreground placeholder:text-muted-foreground/70" required />
            </div>
          </div>

          {error && <p className="text-xs font-mono text-red-400">{error}</p>}

          <Button type="submit" disabled={loading} className="h-11 w-full rounded-none font-mono text-xs uppercase tracking-[0.28em]">
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <>Create Access Profile <ChevronRight className="h-4 w-4" /></>}
          </Button>

          <p className="text-center font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground/80">
            Secure access gateway for PRAHAAR operators
          </p>
        </form>
      </CardContent>
    </Card>
  );
}

/* ── Auth Page ────────────────────────────────────────── */
export default function AuthPage() {
  return (
    <div className="relative min-h-screen overflow-hidden bg-background text-foreground scanline">
      <Navigation currentPage="Authentication" variant="bar" enableHomeHotkey />

      <div className="absolute inset-0 cyber-grid opacity-30" />
      <div className="absolute left-1/2 top-1/2 h-[42rem] w-[42rem] -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary/10 blur-[140px]" />
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-primary/35 to-transparent" />

      <main className="relative z-10 mx-auto flex min-h-screen max-w-7xl flex-col justify-center px-6 pb-16 pt-28 lg:px-8">
        <section className="grid items-center gap-10 lg:grid-cols-[1.1fr_0.9fr]">
          <div className="max-w-2xl">
            <div className="inline-flex items-center gap-3 rounded-full border border-white/10 bg-white/5 px-4 py-1.5 backdrop-blur-md">
              <span className="h-2 w-2 rounded-full bg-primary animate-pulse" />
              <span className="font-mono text-xs uppercase tracking-[0.32em] text-muted-foreground">
                PRAHAAR ACCESS NODE
              </span>
            </div>

            <h1 className="mt-8 font-display text-5xl font-bold leading-none tracking-tight text-transparent bg-clip-text bg-gradient-to-b from-white via-white/85 to-white/25 text-glow md:text-7xl">
              Sign In.
              <br />
              Sign Up.
              <br />
              Enter The Grid.
            </h1>

            <p className="mt-6 max-w-xl text-lg leading-relaxed text-muted-foreground">
              Authenticate before entering the PRAHAAR Command Center. The interface stays consistent with the live cyberwar environment and keeps operator access focused.
            </p>

            <div className="mt-10 grid gap-4 sm:grid-cols-2">
              <div className="glass-panel rounded-xl border border-white/10 p-5">
                <ShieldCheck className="h-5 w-5 text-primary" />
                <h2 className="mt-4 font-display text-xl text-foreground">Secure Operator Access</h2>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                  Role-based entry layout for red-team and blue-team simulation workflows.
                </p>
              </div>

              <div className="glass-panel rounded-xl border border-white/10 p-5">
                <UserPlus className="h-5 w-5 text-primary" />
                <h2 className="mt-4 font-display text-xl text-foreground">Rapid Team Onboarding</h2>
                <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                  A clean registration surface for new analysts joining the PRAHAAR battle environment.
                </p>
              </div>
            </div>
          </div>

          <div>
            <Tabs defaultValue="signin" className="w-full">
              <TabsList className="grid h-auto w-full grid-cols-2 rounded-none border border-white/10 bg-white/5 p-1 backdrop-blur-md">
                <TabsTrigger
                  value="signin"
                  className="rounded-none font-mono text-xs uppercase tracking-[0.24em] data-[state=active]:bg-background/90"
                >
                  Sign In
                </TabsTrigger>
                <TabsTrigger
                  value="signup"
                  className="rounded-none font-mono text-xs uppercase tracking-[0.24em] data-[state=active]:bg-background/90"
                >
                  Sign Up
                </TabsTrigger>
              </TabsList>

              <TabsContent value="signin" className="mt-4">
                <SignInForm />
              </TabsContent>

              <TabsContent value="signup" className="mt-4">
                <SignUpForm />
              </TabsContent>
            </Tabs>
          </div>
        </section>
      </main>
    </div>
  );
}