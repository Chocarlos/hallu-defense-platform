"use client";

import { useLayoutEffect, useRef, type ReactNode } from "react";

import styles from "./marketing.module.css";

export function Reveal({
  children,
  className = ""
}: Readonly<{ children: ReactNode; className?: string | undefined }>) {
  const nodeRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const node = nodeRef.current;
    const pendingClass = styles.revealPending;
    const visibleClass = styles.revealVisible;
    if (
      node === null ||
      pendingClass === undefined ||
      visibleClass === undefined ||
      window.matchMedia("(prefers-reduced-motion: reduce)").matches ||
      !("IntersectionObserver" in window)
    ) {
      return;
    }

    let fallback = 0;
    try {
      const observer = new IntersectionObserver(
        (entries) => {
          if (entries.some((entry) => entry.isIntersecting)) {
            node.classList.remove(pendingClass);
            node.classList.add(visibleClass);
            observer.disconnect();
            window.clearTimeout(fallback);
          }
        },
        { rootMargin: "0px 0px -8%", threshold: 0.12 }
      );
      observer.observe(node);
      node.classList.add(pendingClass);
      fallback = window.setTimeout(() => {
        node.classList.remove(pendingClass);
        node.classList.add(visibleClass);
        observer.disconnect();
      }, 5_000);
      return () => {
        observer.disconnect();
        window.clearTimeout(fallback);
        node.classList.remove(pendingClass);
      };
    } catch {
      return;
    }
  }, []);

  return (
    <div ref={nodeRef} className={`${styles.reveal} ${className}`}>
      {children}
    </div>
  );
}
