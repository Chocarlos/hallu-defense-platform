from __future__ import annotations

import os
import sys
from collections.abc import Collection

LANES = ("auto", "live", "posix", "windows")
PLATFORM_MARKERS = frozenset({"linux", "posix", "windows"})


def current_platform_markers() -> frozenset[str]:
    if os.name == "nt":
        return frozenset({"windows"})
    markers = {"posix"}
    if sys.platform.startswith("linux"):
        markers.add("linux")
    return frozenset(markers)


def selected_for_lane(
    marker_names: Collection[str],
    *,
    lane: str,
    platform_markers: Collection[str],
) -> bool:
    if lane not in LANES:
        raise ValueError(f"Unknown test lane: {lane}")
    names = frozenset(marker_names)
    available = frozenset(platform_markers)
    required_platforms = names & PLATFORM_MARKERS
    if required_platforms and not required_platforms & available:
        return False
    if lane == "auto":
        return "live" not in names
    if lane == "live":
        return "live" in names
    if lane == "windows":
        return "live" not in names and "windows" in names and "windows" in available
    return (
        "live" not in names
        and bool(names & {"posix", "linux"})
        and bool(available & {"posix", "linux"})
    )
