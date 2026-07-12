from __future__ import annotations

import pytest

from scripts.ci.test_lanes import selected_for_lane


@pytest.mark.parametrize(
    ("markers", "lane", "platform", "expected"),
    [
        (set(), "auto", {"windows"}, True),
        ({"live"}, "auto", {"windows"}, False),
        ({"posix"}, "auto", {"windows"}, False),
        ({"windows"}, "auto", {"windows"}, True),
        ({"windows"}, "auto", {"posix", "linux"}, False),
        ({"posix"}, "auto", {"posix", "linux"}, True),
        ({"linux"}, "auto", {"posix", "linux"}, True),
        ({"linux"}, "auto", {"posix"}, False),
        ({"live"}, "live", {"windows"}, True),
        ({"live", "posix"}, "live", {"windows"}, False),
        ({"live", "posix"}, "live", {"posix", "linux"}, True),
        ({"posix"}, "posix", {"posix", "linux"}, True),
        ({"linux"}, "posix", {"posix", "linux"}, True),
        ({"windows"}, "windows", {"windows"}, True),
        (set(), "windows", {"windows"}, False),
    ],
)
def test_lane_selection_is_explicit_and_platform_compatible(
    markers: set[str],
    lane: str,
    platform: set[str],
    expected: bool,
) -> None:
    assert selected_for_lane(markers, lane=lane, platform_markers=platform) is expected


def test_lane_selection_rejects_unknown_lane() -> None:
    with pytest.raises(ValueError, match="Unknown test lane"):
        selected_for_lane(set(), lane="unknown", platform_markers={"windows"})
