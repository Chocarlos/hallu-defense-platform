export interface E2eApiLifecycleDependencies {
  readonly preflight: () => void;
  readonly preCleanup: () => void;
  readonly prepareState: () => void;
  readonly buildSandbox: () => void;
  readonly serveApi: () => Promise<void>;
  readonly finalCleanup: () => void;
}

/**
 * Keeps Docker outside the import preflight and guarantees final cleanup after
 * any partial startup that could have created scratch state or an image tag.
 */
export async function runE2eApiLifecycle(
  dependencies: E2eApiLifecycleDependencies
): Promise<void> {
  dependencies.preflight();
  try {
    dependencies.preCleanup();
    dependencies.prepareState();
    dependencies.buildSandbox();
    await dependencies.serveApi();
  } finally {
    dependencies.finalCleanup();
  }
}
