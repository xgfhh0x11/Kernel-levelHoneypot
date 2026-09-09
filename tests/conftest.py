"""Shared fixtures: repo root and a locator for the built user-mode
control app. The kernel driver needs a WDK + privileged VM, so tests
target the structure and the user-mode app (the part runnable in CI)."""
import glob
import os

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.dirname(_HERE)


@pytest.fixture(scope="session")
def repo_root():
    return _REPO_ROOT


@pytest.fixture(scope="session")
def control_app():
    # Built either by the cl one-liner (repo root or UserModeApp/) or by
    # MSBuild (UserModeApp/x64/<Config>/).
    patterns = [
        os.path.join(_REPO_ROOT, "HoneyPotControl.exe"),
        os.path.join(_REPO_ROOT, "UserModeApp", "HoneyPotControl.exe"),
        os.path.join(_REPO_ROOT, "UserModeApp", "**", "HoneyPotControl.exe"),
    ]
    for pat in patterns:
        hits = glob.glob(pat, recursive=True)
        if hits:
            return hits[0]
    pytest.skip("HoneyPotControl.exe not built — build UserModeApp first (built in CI)")
