from __future__ import annotations

import dodomain


def test_version_is_the_single_source_of_truth() -> None:
    assert dodomain.__version__ == "0.1.0"
