"use client";

import { useEffect, useReducer, useRef, useState, type KeyboardEvent } from "react";
import { Pause, Play } from "lucide-react";

import type { MarketingCopy } from "../../lib/marketing/content";
import {
  INITIAL_TOUR_PLAYBACK,
  reduceTourPlayback
} from "../../lib/marketing/tour-playback";
import styles from "./marketing.module.css";

const TOUR_INTERVAL_MS = 6500;

export function PlatformTour({ copy }: Readonly<{ copy: MarketingCopy["tour"] }>) {
  const [playback, dispatch] = useReducer(
    reduceTourPlayback,
    INITIAL_TOUR_PLAYBACK
  );
  const [reducedMotion, setReducedMotion] = useState(false);
  const tabRefs = useRef<Array<HTMLButtonElement | null>>([]);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    let initialized = false;
    const sync = () => {
      setReducedMotion(media.matches);
      if (media.matches) {
        dispatch({ type: "stop" });
      } else if (!initialized) {
        dispatch({ type: "start" });
      }
      initialized = true;
    };
    sync();
    media.addEventListener("change", sync);
    return () => media.removeEventListener("change", sync);
  }, []);

  useEffect(() => {
    if (!playback.autoRunning || reducedMotion) return;
    const interval = window.setInterval(
      () => dispatch({ type: "tick", stepCount: copy.steps.length }),
      TOUR_INTERVAL_MS
    );
    return () => window.clearInterval(interval);
  }, [playback.autoRunning, copy.steps.length, reducedMotion]);

  const firstStep = copy.steps[0];
  if (firstStep === undefined) return null;
  const activeIndex = playback.activeIndex;
  const autoRunning = playback.autoRunning;

  function select(index: number, focus = false): void {
    dispatch({ type: "select", index });
    if (focus) tabRefs.current[index]?.focus();
  }

  function handleKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number): void {
    if (
      event.key !== "ArrowLeft" &&
      event.key !== "ArrowRight" &&
      event.key !== "Home" &&
      event.key !== "End"
    ) {
      return;
    }
    event.preventDefault();
    if (event.key === "Home" || event.key === "End") {
      select(event.key === "Home" ? 0 : copy.steps.length - 1, true);
      return;
    }
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
            onFocus={() => dispatch({ type: "stop" })}
            onKeyDown={(event) => handleKeyDown(event, index)}
          >
            <span>{item.index}</span>
            {item.label}
          </button>
        ))}
      </div>

      <div className={styles.tourPanelWrap}>
        {copy.steps.map((item, index) => (
          <div
            key={item.key}
            className={styles.tourPanel}
            role="tabpanel"
            id={`tour-panel-${item.key}`}
            aria-labelledby={`tour-tab-${item.key}`}
            aria-live="polite"
            hidden={index !== activeIndex}
          >
            <div className={styles.tourPulse} aria-hidden="true">
              <span>{item.index}</span>
            </div>
            <div>
              <p className={styles.tourLabel}>{item.label}</p>
              <h3>{item.title}</h3>
              <p>{item.body}</p>
              <code>{item.detail}</code>
            </div>
          </div>
        ))}
        <div className={styles.tourControls}>
          <span role="status">{autoRunning && !reducedMotion ? copy.running : copy.stopped}</span>
          {!reducedMotion ? (
            <button
              type="button"
              className={styles.textButton}
              onClick={() => dispatch({ type: "toggle" })}
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
