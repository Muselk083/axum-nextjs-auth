import React from "react";

interface GlowTextProps {
  as?: React.ElementType; // Fix: Use React.ElementType for the 'as' prop
  className?: string;
  children: React.ReactNode;
}

export function GlowText({
  as: Component = "span",
  className,
  children,
}: GlowTextProps) {
  return (
    <Component
      className={`relative text-green-400 font-bold transition-all duration-300 ${className}`}
      style={{
        textShadow: "0 0 8px currentColor, 0 0 16px currentColor",
        animation: "glow 1.5s ease-in-out infinite alternate",
      }}
    >
      {children}
    </Component>
  );
}
