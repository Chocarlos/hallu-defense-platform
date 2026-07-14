import { describe, expect, it } from "vitest";

import {
  INITIAL_TOUR_PLAYBACK,
  reduceTourPlayback
} from "./tour-playback";

describe("tour playback", () => {
  it("starts after hydration and cycles with deterministic wraparound", () => {
    const started = reduceTourPlayback(INITIAL_TOUR_PLAYBACK, { type: "start" });
    const second = reduceTourPlayback(started, { type: "tick", stepCount: 2 });
    const wrapped = reduceTourPlayback(second, { type: "tick", stepCount: 2 });

    expect(started).toEqual({ activeIndex: 0, autoRunning: true });
    expect(second).toEqual({ activeIndex: 1, autoRunning: true });
    expect(wrapped).toEqual({ activeIndex: 0, autoRunning: true });
  });

  it("makes keyboard or pointer selection stop queued automatic ticks", () => {
    const selected = reduceTourPlayback(
      { activeIndex: 0, autoRunning: true },
      { type: "select", index: 3 }
    );
    const afterQueuedTick = reduceTourPlayback(selected, {
      type: "tick",
      stepCount: 4
    });

    expect(selected).toEqual({ activeIndex: 3, autoRunning: false });
    expect(afterQueuedTick).toBe(selected);
  });

  it("keeps SSR/no-JS and reduced-motion playback stopped", () => {
    expect(INITIAL_TOUR_PLAYBACK).toEqual({ activeIndex: 0, autoRunning: false });
    expect(
      reduceTourPlayback(
        { activeIndex: 2, autoRunning: true },
        { type: "stop" }
      )
    ).toEqual({ activeIndex: 2, autoRunning: false });
  });
});
