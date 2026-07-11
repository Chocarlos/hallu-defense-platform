"""Materialize the configured metrics scrape credential for Prometheus."""

from __future__ import annotations

import argparse
import signal
import sys
import threading
from collections.abc import Sequence
from pathlib import Path
from types import FrameType
from typing import TextIO

from hallu_defense.config import load_settings
from hallu_defense.services.metrics_token_materializer import (
    DEFAULT_METRICS_BEARER_TOKEN_FILE,
    MAX_REFRESH_INTERVAL_SECONDS,
    MIN_REFRESH_INTERVAL_SECONDS,
    AtomicSecretFileWriter,
    MetricsBearerTokenMaterializer,
    MetricsTokenMaterializationError,
)
from hallu_defense.services.secrets import create_secret_manager

DEFAULT_REFRESH_INTERVAL_SECONDS = 60.0


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        settings = load_settings()
        secret_name = settings.metrics_bearer_token_secret_name
        if secret_name is None or not secret_name.strip():
            raise MetricsTokenMaterializationError(
                "Metrics bearer token secret name is not configured."
            )
        materializer = MetricsBearerTokenMaterializer(
            secret_manager=create_secret_manager(settings),
            secret_name=secret_name,
            writer=AtomicSecretFileWriter(args.output),
        )
        if args.watch:
            stop_signal = threading.Event()
            _install_signal_handlers(stop_signal)
            print("Metrics bearer token watch started.", file=stdout)
            materializer.watch(
                interval_seconds=args.interval_seconds,
                stop_signal=stop_signal,
                on_error=lambda: print(
                    "Metrics bearer token refresh failed; previous file retained.",
                    file=stderr,
                ),
            )
            print("Metrics bearer token watch stopped.", file=stdout)
        else:
            materializer.materialize()
            print("Metrics bearer token file materialized.", file=stdout)
    except KeyboardInterrupt:
        print("Metrics bearer token watch stopped.", file=stdout)
        return 0
    except Exception:
        print("Metrics bearer token materialization failed.", file=stderr)
        return 1
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Materialize the configured metrics bearer token without printing it."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_METRICS_BEARER_TOKEN_FILE,
        help="Absolute Prometheus authorization.credentials_file path.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Refresh the token until SIGINT or SIGTERM.",
    )
    parser.add_argument(
        "--interval-seconds",
        type=float,
        default=DEFAULT_REFRESH_INTERVAL_SECONDS,
        help=(
            "Watch refresh interval; must be between "
            f"{MIN_REFRESH_INTERVAL_SECONDS:g} and {MAX_REFRESH_INTERVAL_SECONDS:g} seconds."
        ),
    )
    return parser


def _install_signal_handlers(stop_signal: threading.Event) -> None:
    def request_stop(signum: int, frame: FrameType | None) -> None:
        del signum, frame
        stop_signal.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
