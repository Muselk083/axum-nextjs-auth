import { ReactNode } from "react";

export function GlowText({
  as: Tag = "span",
  children,
  className = "",
}: {
  as?: any;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Tag className={`${className} drop-shadow-[0_0_8px_rgba(34,211,238,0.6)]`}>
      {children}
    </Tag>
  );
}
