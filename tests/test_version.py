from __future__ import annotations

import dodomain


def test_version_is_the_single_source_of_truth() -> None:
    assert dodomain.__version__ == "0.5.0"


def test_the_user_agent_reports_that_same_version() -> None:
    # `hatch` reads the version out of __init__.py and the client stamps it onto
    # every request, so a bump that misses one of the two is invisible until a
    # support conversation about "which SDK version sent this".
    client = dodomain.DoDomain(secret_key="dd_sk_test_key")
    assert client.user_agent == f"dodomain-python/{dodomain.__version__}"
