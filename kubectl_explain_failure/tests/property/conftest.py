import os

import pytest

hypothesis = pytest.importorskip(
    "hypothesis",
    reason="Install hypothesis to run property tests: pip install hypothesis",
)
from hypothesis import HealthCheck, settings

settings.register_profile(
    "fast",
    max_examples=80,
    suppress_health_check=[HealthCheck.too_slow],
)

settings.register_profile(
    "deep",
    max_examples=350,
    suppress_health_check=[HealthCheck.too_slow],
)

settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "fast"))
