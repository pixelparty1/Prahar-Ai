import { createContext, useContext, useEffect, useMemo, useState } from "react";

export type ThemeName = "midnight" | "crimson" | "monochrome" | "obsidian" | "sahara" | "classic";

interface ThemeColors {
  primary: string;
  secondary: string;
  accent: string;
  background: string;
  surface: string;
  textPrimary: string;
  textSecondary: string;
  border: string;
  danger: string;
  robotPrimary: string;
  robotSecondary: string;
  robotAccent: string;
}

interface Theme {
  name: ThemeName;
  displayName: string;
  colors: ThemeColors;
}

export const themes: Record<ThemeName, Theme> = {
  midnight: {
    name: "midnight",
    displayName: "Midnight Command",
    colors: {
      primary: "#00CCFF",
      secondary: "#0066FF",
      accent: "#00FF88",
      background: "#0A0E27",
      surface: "#151B3B",
      textPrimary: "#E0E0E0",
      textSecondary: "#9CA3AF",
      border: "rgba(0, 204, 255, 0.3)",
      danger: "#FF3333",
      robotPrimary: "#00CCFF",
      robotSecondary: "#0066FF",
      robotAccent: "#00FF88",
    },
  },
  crimson: {
    name: "crimson",
    displayName: "Crimson Shadow",
    colors: {
      primary: "#C41E3A",
      secondary: "#8B2635",
      accent: "#FF6B7A",
      background: "#1A1A1A",
      surface: "#2D2D2D",
      textPrimary: "#E8E8E8",
      textSecondary: "#A0A0A0",
      border: "rgba(196, 30, 58, 0.3)",
      danger: "#FF4757",
      robotPrimary: "#C41E3A",
      robotSecondary: "#8B2635",
      robotAccent: "#FF6B7A",
    },
  },
  monochrome: {
    name: "monochrome",
    displayName: "Monochrome Elite",
    colors: {
      primary: "#FFFFFF",
      secondary: "#E5E5E5",
      accent: "#CCCCCC",
      background: "#000000",
      surface: "#1C1C1C",
      textPrimary: "#FFFFFF",
      textSecondary: "#B3B3B3",
      border: "rgba(255, 255, 255, 0.2)",
      danger: "#888888",
      robotPrimary: "#FFFFFF",
      robotSecondary: "#E5E5E5",
      robotAccent: "#CCCCCC",
    },
  },
  obsidian: {
    name: "obsidian",
    displayName: "Royal Obsidian",
    colors: {
      primary: "#6B7280",
      secondary: "#4B5563",
      accent: "#9CA3AF",
      background: "#111827",
      surface: "#1F2937",
      textPrimary: "#F9FAFB",
      textSecondary: "#D1D5DB",
      border: "rgba(107, 114, 128, 0.3)",
      danger: "#8B8B8B",
      robotPrimary: "#6B7280",
      robotSecondary: "#4B5563",
      robotAccent: "#9CA3AF",
    },
  },
  sahara: {
    name: "sahara",
    displayName: "Sahara Dusk",
    colors: {
      primary: "#D4A574",
      secondary: "#B8956A",
      accent: "#E8C9A0",
      background: "#2C2416",
      surface: "#3D3428",
      textPrimary: "#F5E6D3",
      textSecondary: "#C9B89A",
      border: "rgba(212, 165, 116, 0.3)",
      danger: "#D4745A",
      robotPrimary: "#D4A574",
      robotSecondary: "#B8956A",
      robotAccent: "#E8C9A0",
    },
  },
  classic: {
    name: "classic",
    displayName: "Classic Dark",
    colors: {
      primary: "#3B82F6",
      secondary: "#1E40AF",
      accent: "#10B981",
      background: "#0F172A",
      surface: "#1E293B",
      textPrimary: "#F1F5F9",
      textSecondary: "#94A3B8",
      border: "rgba(59, 130, 246, 0.2)",
      danger: "#EF4444",
      robotPrimary: "#3B82F6",
      robotSecondary: "#1E40AF",
      robotAccent: "#10B981",
    },
  },
};

interface ThemeContextValue {
  currentTheme: Theme;
  setTheme: (theme: ThemeName) => void;
  themeName: ThemeName;
}

const ThemeContext = createContext<ThemeContextValue | undefined>(undefined);

function hexToHslTokens(hex: string): string {
  const normalized = hex.replace("#", "");
  const full = normalized.length === 3
    ? normalized.split("").map((char) => `${char}${char}`).join("")
    : normalized;

  const r = parseInt(full.slice(0, 2), 16) / 255;
  const g = parseInt(full.slice(2, 4), 16) / 255;
  const b = parseInt(full.slice(4, 6), 16) / 255;

  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const delta = max - min;

  let h = 0;
  if (delta !== 0) {
    if (max === r) h = ((g - b) / delta) % 6;
    else if (max === g) h = (b - r) / delta + 2;
    else h = (r - g) / delta + 4;
  }

  h = Math.round(h * 60);
  if (h < 0) h += 360;

  const l = (max + min) / 2;
  const s = delta === 0 ? 0 : delta / (1 - Math.abs(2 * l - 1));

  return `${h} ${Math.round(s * 100)}% ${Math.round(l * 100)}%`;
}

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [themeName, setThemeName] = useState<ThemeName>(() => {
    if (typeof window === "undefined") {
      return "midnight";
    }

    const saved = window.localStorage.getItem("prahaar-theme") as ThemeName | null;
    return saved && themes[saved] ? saved : "midnight";
  });

  const currentTheme = useMemo(() => themes[themeName], [themeName]);

  useEffect(() => {
    const root = document.documentElement;
    const { colors } = currentTheme;

    root.style.setProperty("--theme-name", currentTheme.displayName);
    root.style.setProperty("--theme-primary", colors.primary);
    root.style.setProperty("--theme-secondary", colors.secondary);
    root.style.setProperty("--theme-accent", colors.accent);
    root.style.setProperty("--theme-background", colors.background);
    root.style.setProperty("--theme-surface", colors.surface);
    root.style.setProperty("--theme-text-primary", colors.textPrimary);
    root.style.setProperty("--theme-text-secondary", colors.textSecondary);
    root.style.setProperty("--theme-border", colors.border);
    root.style.setProperty("--theme-danger", colors.danger);
    root.style.setProperty("--robot-primary", colors.robotPrimary);
    root.style.setProperty("--robot-secondary", colors.robotSecondary);
    root.style.setProperty("--robot-accent", colors.robotAccent);

    root.style.setProperty("--primary", hexToHslTokens(colors.primary));
    root.style.setProperty("--secondary", hexToHslTokens(colors.secondary));
    root.style.setProperty("--accent", hexToHslTokens(colors.accent));
    root.style.setProperty("--background", hexToHslTokens(colors.background));
    root.style.setProperty("--foreground", hexToHslTokens(colors.textPrimary));
    root.style.setProperty("--card", hexToHslTokens(colors.surface));
    root.style.setProperty("--card-foreground", hexToHslTokens(colors.textPrimary));
    root.style.setProperty("--popover", hexToHslTokens(colors.surface));
    root.style.setProperty("--popover-foreground", hexToHslTokens(colors.textPrimary));
    root.style.setProperty("--muted", hexToHslTokens(colors.secondary));
    root.style.setProperty("--muted-foreground", hexToHslTokens(colors.textSecondary));
    root.style.setProperty("--destructive", hexToHslTokens(colors.danger));
    root.style.setProperty("--destructive-foreground", hexToHslTokens(colors.textPrimary));
    root.style.setProperty("--input", hexToHslTokens(colors.surface));
    root.style.setProperty("--border", hexToHslTokens(colors.secondary));
    root.style.setProperty("--ring", hexToHslTokens(colors.primary));

    window.localStorage.setItem("prahaar-theme", themeName);
    document.body.dataset.theme = themeName;
  }, [currentTheme, themeName]);

  return (
    <ThemeContext.Provider
      value={{
        currentTheme,
        setTheme: setThemeName,
        themeName,
      }}
    >
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme() {
  const context = useContext(ThemeContext);
  if (!context) {
    throw new Error("useTheme must be used within ThemeProvider");
  }
  return context;
}
