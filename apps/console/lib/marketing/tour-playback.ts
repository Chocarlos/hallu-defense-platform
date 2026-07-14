export interface TourPlaybackState {
  readonly activeIndex: number;
  readonly autoRunning: boolean;
}

export type TourPlaybackEvent =
  | { readonly type: "start" }
  | { readonly type: "stop" }
  | { readonly type: "toggle" }
  | { readonly type: "select"; readonly index: number }
  | { readonly type: "tick"; readonly stepCount: number };

export const INITIAL_TOUR_PLAYBACK: TourPlaybackState = Object.freeze({
  activeIndex: 0,
  autoRunning: false
});

export function reduceTourPlayback(
  state: TourPlaybackState,
  event: TourPlaybackEvent
): TourPlaybackState {
  switch (event.type) {
    case "start":
      return { ...state, autoRunning: true };
    case "stop":
      return { ...state, autoRunning: false };
    case "toggle":
      return { ...state, autoRunning: !state.autoRunning };
    case "select":
      return { activeIndex: event.index, autoRunning: false };
    case "tick":
      if (!state.autoRunning || event.stepCount <= 0) {
        return state;
      }
      return {
        ...state,
        activeIndex: (state.activeIndex + 1) % event.stepCount
      };
  }
}
