from __future__ import annotations

from typing import Any

import pytest

from scripts.ci.test_lanes import LANES, current_platform_markers, selected_for_lane


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--suite-lane",
        choices=LANES,
        default="auto",
        help="Select the auto, platform-specific, or live API test lane.",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    lane = str(config.getoption("--suite-lane"))
    platform_markers = current_platform_markers()
    selected: list[pytest.Item] = []
    deselected: list[pytest.Item] = []
    for item in items:
        marker_names = {marker.name for marker in item.iter_markers()}
        target = (
            selected
            if selected_for_lane(
                marker_names,
                lane=lane,
                platform_markers=platform_markers,
            )
            else deselected
        )
        target.append(item)
    if deselected:
        config.hook.pytest_deselected(items=deselected)
    items[:] = selected


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    reporter: Any = session.config.pluginmanager.get_plugin("terminalreporter")
    skipped = [] if reporter is None else reporter.stats.get("skipped", [])
    if skipped and exitstatus == pytest.ExitCode.OK:
        reporter.write_sep(
            "=",
            "runtime skips are forbidden; assign the test to an explicit lane or fail it",
            red=True,
        )
        session.exitstatus = pytest.ExitCode.TESTS_FAILED
