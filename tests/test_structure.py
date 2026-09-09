"""Structure check — asserts the six honeypot layers the README/
ARCHITECTURE document each have a matching <Name>Layer.{c,h} in the
driver, that the driver entry point and user-mode app are present, and
that the driver's .vcxproj actually enumerates every layer source (so a
layer can't be added to the tree but dropped from the build).
Pure-Python; no WDK required."""
import os
import re

import pytest

LAYERS = ["Trigger", "Detection", "Deception", "Logging", "Extraction", "Control"]

DRIVER_DIR = "KernelDriver"
APP_DIR = "UserModeApp"


@pytest.mark.parametrize("layer", LAYERS)
@pytest.mark.parametrize("ext", [".c", ".h"])
def test_layer_source_present(repo_root, layer, ext):
    name = f"{layer}Layer{ext}"
    assert os.path.isfile(os.path.join(repo_root, DRIVER_DIR, name)), f"missing {DRIVER_DIR}/{name}"


@pytest.mark.parametrize("name", ["FakeNetFilter.c", "FakeNetFilter.h", "FakeNetFilter.vcxproj", "sources"])
def test_driver_entry_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, DRIVER_DIR, name)), f"missing {DRIVER_DIR}/{name}"


@pytest.mark.parametrize("name", ["HoneyPotControl.c", "HoneyPotControl.h", "HoneyPotControl.vcxproj"])
def test_usermode_app_present(repo_root, name):
    assert os.path.isfile(os.path.join(repo_root, APP_DIR, name)), f"missing {APP_DIR}/{name}"


def test_vcxproj_enumerates_every_layer(repo_root):
    """Each layer's .c must appear as a ClCompile entry in the driver
    project, so the build and the source tree cannot drift apart."""
    with open(os.path.join(repo_root, DRIVER_DIR, "FakeNetFilter.vcxproj"), "r", encoding="utf-8", errors="replace") as fh:
        proj = fh.read()
    missing = [f"{layer}Layer.c" for layer in LAYERS if f"{layer}Layer.c" not in proj]
    missing += [c for c in ["FakeNetFilter.c"] if c not in proj]
    assert not missing, f"FakeNetFilter.vcxproj does not compile: {missing}"
