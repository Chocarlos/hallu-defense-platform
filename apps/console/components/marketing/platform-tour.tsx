"use client";

import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { Pause, Play } from "lucide-react";

import type { MarketingCopy } from "../../lib/marketing/content";
import styles from "./marketing.module.css";

const TOUR_INTERVAL_MS = 6500;

export function PlatformTour({ copy }: Readonly<{ copy: MarketingCopy["tour"] }>) {
  const [activeIndex, setActiveIndex] = useState(0);
  const [autoRunning, setAutoRunning] = useState(true);
  const [reducedMotion, setReducedMotion] = useState(false);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => {
      setReducedMotion(media.matches);
      if (media.matches) setAutoRunning(false);
    };
    sync();
    media.addEventListener("change", sync);
    return () => media.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    if (!autoRunning || reducedMotion) return;
    const interval = window.setInterval(
      () => setActiveIndex((current) => (current + 1) % copy.steps.length),
      TOUR_INTERVAL_MS
    );
    return () => window.clearInterval(interval);
  }, [autoRunning, copy.steps.length, reducedMotion]);

  const firstStep = copy.steps[0];
  if (firstStep === undefined) return null;
  const step = copy.steps[activeIndex] ?? firstStep;

  function select(index: number, focus = false): void {
    setAutoRunning(false);
    setActiveIndex(index);
    if (focus) tabRefs.current[index]?.focus();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number): void {
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const offset = event.key === "ArrowRight" ? 1 : -1;
    select((index + offset + copy.steps.length) % copy.steps.length, true);
  }

  return (
    <div className={styles.tourShell}>
      <div className={styles.tourTabs} role="tablist" aria-label={copy.tabsLabel}>
        {copy.steps.map((item, index) => (
          <button
            key={item.key}
            ref={(node) => {
              tabRefs.current[index] = node;
            }}
            className={`${styles.tourTab} ${index === activeIndex ? styles.tourTabActive : ""}`}
            type="button"
            role="tab"
            id={`tour-tab-${item.key}`}
            aria-controls={`tour-panel-${item.key}`}
            aria-selected={index === activeIndex}
            tabIndex={index === activeIndex ? 0 : -1}
            onClick={() => select(index)}
            onKeyDown={(event) => handleKeyDown(event, index)}
          >
            <span>{item.index}</span>
            {item.label}
          </button>
        ))}
      </div>

      <div className={styles.tourPanelWrap}>
        <article
          className={styles.tourPanel}
          role="tabpanel"
          id={`tour-panel-${step.key}`}
          aria-labelledby={`tour-tab-${step.key}`}
          aria-live="polite"
        >
          <div className={styles.tourPulse} aria-hidden="true">
            <span>{step.index}</span>
          </div>
          <div>
            <p className={styles.tourLabel}>{step.label}</p>
            <h3>{step.title}</h3>
            <p>{step.body}</p>
            <code>{step.detail}</code>
          </div>
        </article>
        <div className={styles.tourControls}>
          <span role="status">{autoRunning && !reducedMotion ? copy.running : copy.stopped}</span>
          {!reducedMotion ? (
            <button
              type="button"
              className={styles.textButton}
              onClick={() => setAutoRunning((current) => !current)}
            >
              {autoRunning ? <Pause aria-hidden="true" size={15} /> : <Play aria-hidden="true" size={15} />}
              {autoRunning ? copy.pause : copy.resume}
            </button>
          ) : null}
        </div>
      </div>
    </div>
  );
}
