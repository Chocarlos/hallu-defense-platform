export interface SafeConsoleApiError {
  readonly status: number | null;
  readonly message: string;
}

export function safeConsoleApiError(
  error: unknown,
  fallback: string,
  onUnauthorized?: () => void
): SafeConsoleApiError {
  const status = errorStatus(error);
  if (status !== null) {
    if (status === 401) {
      onUnauthorized?.();
      return {
        status: 401,
        message: "La sesion expiro. Inicia sesion nuevamente."
      };
    }
    if (status === 403) {
      return {
        status: 403,
        message: "No tienes permiso para completar esta operacion."
      };
    }
    if (status === 429) {
      return {
        status: 429,
        message: "Demasiadas solicitudes. Espera antes de intentarlo nuevamente."
      };
    }
    if (status === 408) {
      return {
        status: 408,
        message: "La operacion no respondio dentro del tiempo permitido."
      };
    }
    if (status >= 500) {
      return {
        status,
        message: "El servicio no esta disponible temporalmente."
      };
    }
  }
  return { status: null, message: fallback };
}

function errorStatus(error: unknown): number | null {
  if (typeof error !== "object" || error === null || !("status" in error)) {
    return null;
  }
  const status = error.status;
  return typeof status === "number" && Number.isSafeInteger(status) ? status : null;
}
