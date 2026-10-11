#!/usr/bin/env python3
"""Clean-room and negative tests for the UI1 pixel evidence pipeline."""

from __future__ import annotations

import importlib.util
import json
import hashlib
import re
import subprocess
import tempfile
from pathlib import Path

import numpy as np


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
GENERATOR = TOOLS / "generate-ui1-pixel-evidence.py"
BOARD = TOOLS / "generate-ui1-comparison-board.py"
MANIFEST = TOOLS / "ui1-pixel-landmarks-v1.json"


def load_generator():
    spec = importlib.util.spec_from_file_location("ui1_pixel_generator", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def main() -> None:
    source = GENERATOR.read_text(encoding="utf-8")
    assert "Image.open(EVIDENCE / \"ui1-pixel-glyph-mask-alpha-1440x810.png\")" not in source, "generator must not read a generated mask"
    assert "OLD_JSON_PATH" not in source and "ui1-pixel-acceptance.json\").read_text" not in source, "generator must not read generated JSON"
    assert "prior =" not in source and "prior[" not in source, "generator must not carry forward prior evidence"
    assert "bifrost-obsidian-final-reference.png" in source, "generator must use the repository owner reference"
    forbidden = (
        re.compile(r"c:\\users", re.IGNORECASE),
        re.compile(r"\.codex", re.IGNORECASE),
        re.compile(r"generated_images", re.IGNORECASE),
        re.compile(r"(?:^|[/\\])temp(?:[/\\]|$)", re.IGNORECASE),
    )
    for path in (GENERATOR, MANIFEST, BOARD):
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            assert not pattern.search(text), f"non-portable default path {pattern.pattern!r} in {path}"

    generator = load_generator()
    with tempfile.TemporaryDirectory(prefix="bifrost-ui1-clean-room-") as temp:
        output = Path(temp)
        assert not list(output.iterdir()), "clean-room output must start empty"
        result = subprocess.run(["python", str(GENERATOR), "--output-dir", str(output)], cwd=ROOT, text=True, capture_output=True)
        assert result.returncode == 0, result.stdout + result.stderr
        board_result = subprocess.run(["python", str(BOARD), "--input-dir", str(output), "--output-dir", str(output)], cwd=ROOT, text=True, capture_output=True)
        assert board_result.returncode == 0, board_result.stdout + board_result.stderr
        required = {"reference-normalized-1440x810.png", "ui1-windows-protected-overlay-1440x810.png", "ui1-windows-protected-diff-heatmap-1440x810.png", "ui1-pixel-glyph-mask-1440x810.png", "ui1-pixel-glyph-mask-alpha-1440x810.png", "ui1-pixel-acceptance.json", "UI1-obsidian-comparison-board-1440x900.png", "UI1-obsidian-comparison-board.html"}
        assert required <= {item.name for item in output.iterdir()}
        pixel = json.loads((output / "ui1-pixel-acceptance.json").read_text(encoding="utf-8"))
        expected_reference = generator.DEFAULT_REFERENCE.resolve()
        assert pixel["inputProvenance"]["ownerReference"] == str(expected_reference)
        assert pixel["inputProvenance"]["ownerReferenceSha256"] == generator.OWNER_REFERENCE_SHA256
        assert pixel["inputProvenance"]["ownerReferenceSha256"] == hashlib.sha256(expected_reference.read_bytes()).hexdigest()
        assert pixel["inputProvenance"]["ownerReferenceDimensions"] == {"width": 1672, "height": 941}
        assert pixel["inputProvenance"]["generatedInputs"] == []
        assert pixel["inputProvenance"]["maskInput"].endswith("ui1-pixel-landmarks-v1.json")
        assert pixel["maskArtifacts"]["coveragePercent"] <= 10
        assert pixel["maskArtifacts"]["structurePixelsMasked"] == 0
        assert pixel["metrics"]["edgeSsim"] >= 0.85
        assert pixel["metrics"]["edgeSsimStrictThreshold04"] != pixel["metrics"]["edgeSsim"]
        assert pixel["metrics"]["edgeSsimStrictGaussianSigma2Threshold04"] != pixel["metrics"]["edgeSsimStrictThreshold04"]
        assert pixel["dialGeometry"]["centerPass"] and pixel["dialGeometry"]["sizePass"]
        for name in ("topSegmented", "bottomMode", "dial"):
            reference = pixel["referenceBounds"][name]
            actual = pixel["actualBounds"][name]
            declared = pixel["delta"][name]
            for key in ("x", "y", "width", "height"):
                assert declared[key] == actual[key] - reference[key], (name, key, declared[key], actual[key], reference[key])
        assert pixel["status"] == "PASS"

        tampered = output / "tampered-reference.png"
        tampered_bytes = bytearray(expected_reference.read_bytes())
        tampered_bytes[-1] ^= 0x01
        tampered.write_bytes(tampered_bytes)
        tampered_output = output / "tampered-output"
        tampered_result = subprocess.run(
            ["python", str(GENERATOR), "--output-dir", str(tampered_output), "--reference", str(tampered)],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        assert tampered_result.returncode != 0, "a one-byte reference mutation must fail closed"
        assert "SHA-256 mismatch" in (tampered_result.stdout + tampered_result.stderr)

    structure = np.zeros((100, 100), dtype=bool)
    mask = np.zeros((100, 100), dtype=bool)
    structure[10, 10] = True; mask[10, 10] = True
    try:
        generator.validate_mask(mask, structure)
    except generator.EvidenceIntegrityError:
        pass
    else:
        raise AssertionError("structure overlap negative case did not fail")
    structure.fill(False); mask[:11, :] = True
    try:
        generator.validate_mask(mask, structure)
    except generator.EvidenceIntegrityError:
        pass
    else:
        raise AssertionError("coverage negative case did not fail")
    print("UI1_PIXEL_EVIDENCE_INTEGRITY_PASS clean-room=1 arithmetic=1 structure-negative=1 coverage-negative=1 dependency-audit=1 static-path-audit=1 reference-provenance=1 tampered-reference-negative=1")


if __name__ == "__main__":
    main()
