import { useEffect, useRef } from "react";

export function CursorGlow() {
  const glowRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const glow = glowRef.current;
    if (!glow) {
      return;
    }

    let frameId = 0;

    const moveGlow = (event: MouseEvent) => {
      if (frameId) {
        cancelAnimationFrame(frameId);
      }

      frameId = requestAnimationFrame(() => {
        glow.style.opacity = "1";
        glow.style.transform = `translate3d(${event.clientX - 80}px, ${event.clientY - 80}px, 0)`;
      });
    };

    const hideGlow = () => {
      glow.style.opacity = "0";
    };

    const pressGlow = () => {
      glow.classList.add("cursor-glow--pressed");
    };

    const releaseGlow = () => {
      glow.classList.remove("cursor-glow--pressed");
    };

    window.addEventListener("mousemove", moveGlow);
    window.addEventListener("mouseleave", hideGlow);
    window.addEventListener("mousedown", pressGlow);
    window.addEventListener("mouseup", releaseGlow);

    return () => {
      if (frameId) {
        cancelAnimationFrame(frameId);
      }
      window.removeEventListener("mousemove", moveGlow);
      window.removeEventListener("mouseleave", hideGlow);
      window.removeEventListener("mousedown", pressGlow);
      window.removeEventListener("mouseup", releaseGlow);
    };
  }, []);

  return <div ref={glowRef} className="cursor-glow" aria-hidden="true" />;
}
