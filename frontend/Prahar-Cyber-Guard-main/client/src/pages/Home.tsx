import { motion } from "framer-motion";
import { Link } from "wouter";
import { ChevronRight } from "lucide-react";
import { RobotScene } from "@/components/RobotScene";
import { Navigation } from "@/components/Navigation";
import { useTheme } from "@/contexts/ThemeContext";

export default function Home() {
  const { currentTheme } = useTheme();

  return (
    <div className="relative min-h-screen bg-background text-foreground overflow-hidden scanline">
      <Navigation currentPage="Home" variant="bar" />
      {/* Background Effects Layers */}
      <div className="absolute inset-0 z-0 bg-transparent">
        <div className="absolute inset-0 cyber-grid opacity-30"></div>
        {/* Subtle radial glow in the center */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-primary/10 rounded-full blur-[120px] pointer-events-none"></div>
        {/* Glowing stars behind robot */}
        <div className="absolute inset-0 z-[1] pointer-events-none overflow-hidden mix-blend-screen">
          {Array.from({ length: 80 }).map((_, i) => {
            const size = 2 + Math.random() * 4;
            const top = 10 + Math.random() * 70;
            const left = 15 + Math.random() * 70;
            const dur = 2 + Math.random() * 5;
            const delay = Math.random() * 4;
            const baseOpacity = 0.35 + Math.random() * 0.55;
            return (
              <div
                key={i}
                className="absolute rounded-full bg-white"
                style={{
                  width: `${size}px`,
                  height: `${size}px`,
                  top: `${top}%`,
                  left: `${left}%`,
                  opacity: baseOpacity,
                  boxShadow: `0 0 ${8 + size * 3}px ${2 + size * 1.5}px rgba(255,255,255,${0.35 + Math.random() * 0.3})`,
                  animation: `star-pulse ${dur}s ease-in-out ${delay}s infinite alternate`,
                }}
              />
            );
          })}
        </div>
      </div>

      {/* 3D Scene - Positioned behind UI but catches full mouse events */}
      <RobotScene appTheme={currentTheme.name} />

      {/* Main UI Wrapper - pointer-events-none so mouse passes through to Canvas, 
          re-enabled on specific interactive elements */}
      <div className="relative z-10 min-h-screen flex flex-col pointer-events-none pt-16">

        {/* Hero Content */}
        <main className="flex-1 flex flex-col items-center justify-center px-4 pt-48 md:pt-64 pb-20 text-center">
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, ease: "easeOut" }}
            className="pointer-events-auto flex items-center gap-3 px-4 py-1.5 rounded-full border border-white/10 bg-white/5 backdrop-blur-md mb-8"
          >
            <span className="w-2 h-2 rounded-full bg-primary animate-pulse"></span>
            <span className="font-mono text-xs text-muted-foreground uppercase tracking-widest">
              PRAHAAR COMMAND INTERFACE
            </span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.2, ease: "easeOut" }}
            className="font-display font-bold text-6xl md:text-8xl lg:text-[10rem] leading-none tracking-tighter text-transparent bg-clip-text bg-gradient-to-b from-white via-white/80 to-white/20 text-glow pointer-events-auto drop-shadow-2xl"
          >
            PRAHAAR
          </motion.h1>

          <motion.p
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.7, delay: 0.4, ease: "easeOut" }}
            className="mt-6 max-w-2xl text-lg md:text-xl text-muted-foreground font-light leading-relaxed pointer-events-auto"
          >
            PRAHAAR - Autonomous AI Cyberwar System
            <br />
            Red Team vs Blue Team - Live AI Battle Simulation.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, delay: 0.6, ease: "easeOut" }}
            className="mt-10 flex items-center justify-center pointer-events-auto"
          >
            <Link href="/auth">
              <button className="group relative flex items-center justify-center px-10 py-4 bg-primary text-primary-foreground font-mono font-bold text-sm tracking-wider overflow-hidden">
                <div className="absolute inset-0 w-full h-full bg-white/20 translate-y-full group-hover:translate-y-0 transition-transform duration-300 ease-out"></div>
                <span className="relative z-10 flex items-center">
                  LAUNCH COMMAND CENTER
                  <ChevronRight className="w-4 h-4 ml-2 group-hover:translate-x-1 transition-transform" />
                </span>
                <div className="absolute top-0 left-0 w-2 h-2 border-t-2 border-l-2 border-white/50"></div>
                <div className="absolute bottom-0 right-0 w-2 h-2 border-b-2 border-r-2 border-white/50"></div>
              </button>
            </Link>
          </motion.div>

        </main>
        
        {/* Footer Metrics (Decorative) */}
        <div className="absolute bottom-0 w-full p-6 flex justify-between items-end font-mono text-[10px] text-muted-foreground tracking-widest opacity-50 pointer-events-none">
          <div className="flex flex-col gap-1">
            <span>SYS.STATUS: <span className="text-primary">ONLINE</span></span>
            <span>SEC.LEVEL: MAXIMUM</span>
          </div>
          <div className="text-right flex flex-col gap-1 hidden sm:flex">
            <span>V 2.0.4.881</span>
            <span>PRAHAAR CYBERNETICS // 2024</span>
          </div>
        </div>
      </div>
    </div>
  );
}
