"""Placeholder-honesty guard.

Several kernel-side components ship deliberate, documented placeholders
(XOR "encryption" instead of AES-XTS, a simplified disassembler, a CNN
classifier stub, an unimplemented remote-update channel). Replacing them
with real implementations needs a WDK build + a privileged kernel VM, so
they remain honest scope-limits rather than untested kernel code.

What CAN regress silently is the *disclosure*: someone could leave the
weak implementation in place but delete the comment that says it is a
placeholder, making it look production-grade. These tests pin the
honesty markers so that can't happen unnoticed. They do not require a
toolchain — they read source text.
"""
import os

import pytest

DRIVER = "KernelDriver"


def _read(repo_root, name):
    with open(os.path.join(repo_root, DRIVER, name), "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().lower()


def test_logging_layer_discloses_weak_crypto(repo_root):
    src = _read(repo_root, "LoggingLayer.c")
    assert "placeholder" in src
    assert "not cryptographically secure" in src, (
        "LoggingLayer.c must keep its 'NOT cryptographically secure' disclosure "
        "for the XOR-based logging encryption placeholder"
    )


def test_extraction_layer_discloses_simplified_disassembler(repo_root):
    src = _read(repo_root, "ExtractionLayer.c")
    assert "disassembler" in src and "placeholder" in src, (
        "ExtractionLayer.c must keep the 'simple disassembler (placeholder)' disclosure"
    )


def test_extraction_layer_discloses_cnn_placeholder(repo_root):
    src = _read(repo_root, "ExtractionLayer.h")
    assert "cnn" in src and "placeholder" in src, (
        "ExtractionLayer.h must keep the CNN-classification placeholder disclosure"
    )


def test_control_layer_discloses_unimplemented_remote_update(repo_root):
    src = _read(repo_root, "ControlLayer.c")
    assert "not implemented" in src or "placeholder" in src, (
        "ControlLayer.c must keep the 'remote update (not implemented)' disclosure"
    )
