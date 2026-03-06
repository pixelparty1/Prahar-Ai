import { useEffect, useRef, useState } from "react";
import { Check, Palette } from "lucide-react";
import { ThemeName, themes, useTheme } from "@/contexts/ThemeContext";

export function ThemeSwitcher() {
  const { themeName, setTheme } = useTheme();
  const [isOpen, setIsOpen] = useState(false);
  const ref = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const onClick = (event: MouseEvent) => {
      if (!ref.current?.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    if (isOpen) {
      document.addEventListener("mousedown", onClick);
    }

    return () => document.removeEventListener("mousedown", onClick);
  }, [isOpen]);

  return (
    <div className="relative" ref={ref}>
      <button
        onClick={() => setIsOpen((v) => !v)}
        className="flex items-center gap-2 px-3 py-2 rounded-lg border transition-all duration-300"
        style={{
          background: "var(--theme-surface)",
          borderColor: "var(--theme-border)",
          color: "var(--theme-text-primary)",
        }}
      >
        <Palette className="w-4 h-4" />
        <span className="hidden md:inline">Theme</span>
      </button>

      {isOpen ? (
        <div
          className="absolute right-0 mt-2 w-72 rounded-lg shadow-2xl border overflow-hidden z-50"
          style={{
            background: "var(--theme-surface)",
            borderColor: "var(--theme-border)",
          }}
        >
          <div
            className="px-4 py-3 border-b font-semibold font-mono text-sm"
            style={{
              borderColor: "var(--theme-border)",
              color: "var(--theme-text-primary)",
            }}
          >
            Choose Theme
          </div>

          <div className="p-2">
            {Object.entries(themes).map(([key, theme]) => {
              const active = themeName === key;

              return (
                <button
                  key={key}
                  onClick={() => {
                    setTheme(key as ThemeName);
                    setIsOpen(false);
                  }}
                  className="w-full flex items-center justify-between px-3 py-3 rounded-lg transition-all duration-200"
                  style={{
                    background: active ? "var(--theme-primary)" : "transparent",
                    color: active ? "var(--theme-background)" : "var(--theme-text-primary)",
                  }}
                >
                  <div className="flex items-center gap-3">
                    <div className="flex gap-1">
                      <div className="w-4 h-4 rounded" style={{ background: theme.colors.primary }} />
                      <div className="w-4 h-4 rounded" style={{ background: theme.colors.secondary }} />
                      <div className="w-4 h-4 rounded" style={{ background: theme.colors.accent }} />
                    </div>
                    <div className="flex flex-col items-start">
                      <span className="text-sm font-medium">{theme.displayName}</span>
                      {key === "classic" ? <span className="text-[10px] opacity-70">Original</span> : null}
                    </div>
                  </div>

                  {active ? <Check className="w-4 h-4" /> : null}
                </button>
              );
            })}
          </div>
        </div>
      ) : null}
    </div>
  );
}
