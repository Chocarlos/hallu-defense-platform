export type CoordinatedResult<T> =
  | { readonly kind: "current"; readonly value: T }
  | { readonly kind: "superseded" };

interface InFlight {
  readonly epoch: number;
  readonly fingerprint: string;
  readonly controller: AbortController;
  readonly promise: Promise<CoordinatedResult<unknown>>;
}

export interface RequestCoordinator {
  run<T>(
    channel: string,
    fingerprint: string,
    request: (signal: AbortSignal) => Promise<T>
  ): Promise<CoordinatedResult<T>>;
  abort(channel: string): void;
  abortAll(): void;
}

export function createRequestCoordinator(): RequestCoordinator {
  const epochs = new Map<string, number>();
  const inFlight = new Map<string, InFlight>();

  return {
    run<T>(
      channel: string,
      fingerprint: string,
      request: (signal: AbortSignal) => Promise<T>
    ): Promise<CoordinatedResult<T>> {
      const existing = inFlight.get(channel);
      if (existing?.fingerprint === fingerprint) {
        return existing.promise as Promise<CoordinatedResult<T>>;
      }
      existing?.controller.abort();

      const epoch = (epochs.get(channel) ?? 0) + 1;
      epochs.set(channel, epoch);
      const controller = new AbortController();
      let resolvePromise!: (result: CoordinatedResult<T>) => void;
      let rejectPromise!: (reason: unknown) => void;
      const promise = new Promise<CoordinatedResult<T>>((resolve, reject) => {
        resolvePromise = resolve;
        rejectPromise = reject;
      });
      const entry: InFlight = { epoch, fingerprint, controller, promise };
      inFlight.set(channel, entry);

      void (async (): Promise<void> => {
        try {
          const value = await request(controller.signal);
          resolvePromise(isCurrent(inFlight, channel, epoch, controller)
            ? { kind: "current", value }
            : { kind: "superseded" });
        } catch (error) {
          if (controller.signal.aborted || !isCurrent(inFlight, channel, epoch, controller)) {
            resolvePromise({ kind: "superseded" });
          } else {
            rejectPromise(error);
          }
        } finally {
          const current = inFlight.get(channel);
          if (current?.epoch === epoch && current.controller === controller) {
            inFlight.delete(channel);
          }
        }
      })();
      return promise;
    },
    abort(channel: string): void {
      const entry = inFlight.get(channel);
      if (entry !== undefined) {
        entry.controller.abort();
        inFlight.delete(channel);
      }
      epochs.set(channel, (epochs.get(channel) ?? 0) + 1);
    },
    abortAll(): void {
      for (const [channel, entry] of inFlight) {
        entry.controller.abort();
        epochs.set(channel, (epochs.get(channel) ?? 0) + 1);
      }
      inFlight.clear();
    }
  };
}

function isCurrent(
  inFlight: Map<string, InFlight>,
  channel: string,
  epoch: number,
  controller: AbortController
): boolean {
  const current = inFlight.get(channel);
  return current?.epoch === epoch && current.controller === controller && !controller.signal.aborted;
}
