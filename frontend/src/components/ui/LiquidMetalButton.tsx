import React, { useEffect, useRef, useState, useMemo } from 'react';
import { Sparkles } from 'lucide-react';

interface LiquidMetalButtonProps {
  label?: string;
  onClick?: () => void;
  viewMode?: "text" | "icon";
  className?: string;
}

export function LiquidMetalButton({
  label = "Get Started",
  onClick,
  viewMode = "text",
  className = "",
}: LiquidMetalButtonProps) {
  const [isHovered, setIsHovered] = useState(false);
  const [isPressed, setIsPressed] = useState(false);
  const [ripples, setRipples] = useState<Array<{ x: number; y: number; id: number }>>([]);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const rippleId = useRef(0);
  const animFrameRef = useRef<number | null>(null);

  const dimensions = useMemo(() => {
    if (viewMode === "icon") {
      return { width: 46, height: 46, innerWidth: 42, innerHeight: 42 };
    }
    return { width: 142, height: 46, innerWidth: 138, innerHeight: 42 };
  }, [viewMode]);

  // Metallic animated fluid canvas effect
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let time = 0;
    const render = () => {
      time += isHovered ? 0.05 : 0.02;
      const w = canvas.width;
      const h = canvas.height;
      
      const grad = ctx.createLinearGradient(
        w / 2 + Math.cos(time) * (w / 2),
        h / 2 + Math.sin(time) * (h / 2),
        w / 2 - Math.cos(time) * (w / 2),
        h / 2 - Math.sin(time) * (h / 2)
      );

      grad.addColorStop(0, '#1e1b4b');
      grad.addColorStop(0.35, '#4338ca');
      grad.addColorStop(0.65, '#818cf8');
      grad.addColorStop(1, '#312e81');

      ctx.fillStyle = grad;
      ctx.fillRect(0, 0, w, h);

      // Highlight shimmer stream
      ctx.beginPath();
      ctx.ellipse(
        w / 2 + Math.sin(time * 1.5) * (w * 0.25),
        h / 2 + Math.cos(time * 1.5) * (h * 0.25),
        w * 0.4,
        h * 0.25,
        time,
        0,
        Math.PI * 2
      );
      ctx.fillStyle = 'rgba(199, 210, 254, 0.25)';
      ctx.fill();

      animFrameRef.current = requestAnimationFrame(render);
    };

    render();

    return () => {
      if (animFrameRef.current) cancelAnimationFrame(animFrameRef.current);
    };
  }, [isHovered]);

  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    if (buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const ripple = { x, y, id: rippleId.current++ };

      setRipples((prev) => [...prev, ripple]);
      setTimeout(() => {
        setRipples((prev) => prev.filter((r) => r.id !== ripple.id));
      }, 600);
    }

    onClick?.();
  };

  return (
    <div className={`relative inline-block select-none ${className}`}>
      <div style={{ perspective: "1000px" }}>
        <div
          style={{
            position: "relative",
            width: `${dimensions.width}px`,
            height: `${dimensions.height}px`,
            transformStyle: "preserve-3d",
            transition: "all 0.3s ease",
          }}
        >
          {/* Label / Icon Layer */}
          <div
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: `${dimensions.width}px`,
              height: `${dimensions.height}px`,
              display: "flex",
              alignItems: "center",
              justifyContent: "center",
              gap: "6px",
              transform: "translateZ(20px)",
              zIndex: 30,
              pointerEvents: "none",
            }}
          >
            {viewMode === "icon" ? (
              <Sparkles className="w-4 h-4 text-indigo-200 drop-shadow" />
            ) : (
              <span className="text-xs font-semibold tracking-wide text-indigo-100 drop-shadow-md">
                {label}
              </span>
            )}
          </div>

          {/* Inner Dark Metal Core */}
          <div
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: `${dimensions.width}px`,
              height: `${dimensions.height}px`,
              transform: `translateZ(10px) ${isPressed ? "translateY(1px) scale(0.97)" : "translateY(0) scale(1)"}`,
              transition: "all 0.2s ease",
              zIndex: 20,
            }}
          >
            <div
              className="m-[2px] rounded-full bg-gradient-to-b from-slate-900 to-slate-950 shadow-inner"
              style={{
                width: `${dimensions.innerWidth}px`,
                height: `${dimensions.innerHeight}px`,
              }}
            />
          </div>

          {/* Metallic Shader Canvas Background */}
          <div
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: `${dimensions.width}px`,
              height: `${dimensions.height}px`,
              transform: `translateZ(0px) ${isPressed ? "translateY(1px) scale(0.97)" : "translateY(0) scale(1)"}`,
              transition: "all 0.2s ease",
              zIndex: 10,
            }}
          >
            <div
              className={`h-full w-full rounded-full overflow-hidden transition-all duration-300 ${
                isHovered
                  ? 'ring-2 ring-indigo-400/50 shadow-lg shadow-indigo-500/25'
                  : 'ring-1 ring-indigo-500/30 shadow-md shadow-indigo-950/50'
              }`}
            >
              <canvas
                ref={canvasRef}
                width={dimensions.width}
                height={dimensions.height}
                className="w-full h-full block rounded-full"
              />
            </div>
          </div>

          {/* Button Trigger & Ripples */}
          <button
            ref={buttonRef}
            onClick={handleClick}
            onMouseEnter={() => setIsHovered(true)}
            onMouseLeave={() => {
              setIsHovered(false);
              setIsPressed(false);
            }}
            onMouseDown={() => setIsPressed(true)}
            onMouseUp={() => setIsPressed(false)}
            style={{
              position: "absolute",
              top: 0,
              left: 0,
              width: `${dimensions.width}px`,
              height: `${dimensions.height}px`,
              background: "transparent",
              border: "none",
              cursor: "pointer",
              outline: "none",
              zIndex: 40,
              transform: "translateZ(25px)",
              borderRadius: "100px",
              overflow: "hidden",
            }}
            aria-label={label}
          >
            {ripples.map((ripple) => (
              <span
                key={ripple.id}
                className="animate-ping"
                style={{
                  position: "absolute",
                  left: `${ripple.x}px`,
                  top: `${ripple.y}px`,
                  width: "24px",
                  height: "24px",
                  borderRadius: "50%",
                  background: "radial-gradient(circle, rgba(165, 180, 252, 0.6) 0%, rgba(255, 255, 255, 0) 70%)",
                  transform: "translate(-50%, -50%)",
                  pointerEvents: "none",
                }}
              />
            ))}
          </button>
        </div>
      </div>
    </div>
  );
}
