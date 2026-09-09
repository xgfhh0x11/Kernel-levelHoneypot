"""CLI smoke test for the user-mode control app. `help` is answerable
without the driver loaded (it returns before opening the device), so it
is a valid exit-0 smoke check. Skips when the app has not been built;
runs for real in CI after the MSVC build step."""
import subprocess

import pytest


def _run(app, *args):
    return subprocess.run([app, *args], capture_output=True, text=True, timeout=30)


def test_help_exits_clean_without_driver(control_app):
    res = _run(control_app, "help")
    assert res.returncode == 0, f"`help` exited {res.returncode} (should not need the driver)\n{res.stdout}\n{res.stderr}"
    assert "Usage" in res.stdout, f"`help` did not print usage:\n{res.stdout}"


def test_help_slash_question_alias(control_app):
    res = _run(control_app, "/?")
    assert res.returncode == 0, f"`/?` exited {res.returncode}"
    assert "Usage" in res.stdout
