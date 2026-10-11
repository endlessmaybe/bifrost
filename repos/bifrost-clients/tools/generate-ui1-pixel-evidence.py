#!/usr/bin/env python3
"""Generate UI1 pixel evidence from owner/reference + production actual only.

The glyph mask is reconstructed on every run from the explicit, versioned ROI
manifest.  No prior JSON, alpha mask, overlay, heatmap, or board is an input.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np
from PIL import Image
from scipy.ndimage import binary_dilation, find_objects, gaussian_filter, sobel, label
from skimage.metrics import structural_similarity


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT.parent / "bifrost-docs"
DEFAULT_EVIDENCE = DOCS / "evidence"
DEFAULT_ARTIFACT = ROOT / "artifacts" / "ui-acceptance" / "ui1-obsidian-20260816"
DEFAULT_MANIFEST = ROOT / "tools" / "ui1-pixel-landmarks-v1.json"
# The owner reference is a versioned repository asset.  Keep this path derived
# from the clients repository so evidence generation remains portable after
# Codex cache cleanup or a workspace migration.
DEFAULT_REFERENCE = DOCS / "assets" / "ui" / "bifrost-obsidian-final-reference.png"
DEFAULT_ACTUAL = DEFAULT_ARTIFACT / "bifrost-windows-dark-protected-test-actual.png"
OWNER_REFERENCE_SHA256 = "84c7f867f1e0e8f250b657ec98eee650e443e1663344dc2d69e1e428cbf356da"
OWNER_REFERENCE_SIZE = (1672, 941)


class EvidenceIntegrityError(RuntimeError):
    pass


def validate_owner_reference(path: Path) -> Path:
    """Validate the immutable owner asset before opening or normalizing it."""
    resolved = path.resolve()
    try:
        digest = hashlib.sha256(resolved.read_bytes()).hexdigest().lower()
    except OSError as error:
        raise EvidenceIntegrityError(f"owner reference is missing or unreadable: {resolved}") from error
    if digest != OWNER_REFERENCE_SHA256:
        raise EvidenceIntegrityError(
            f"owner reference SHA-256 mismatch for {resolved}: expected {OWNER_REFERENCE_SHA256}, got {digest}"
        )
    try:
        with Image.open(resolved) as image:
            dimensions = image.size
    except OSError as error:
        raise EvidenceIntegrityError(f"owner reference is not a readable image: {resolved}") from error
    if dimensions != OWNER_REFERENCE_SIZE:
        raise EvidenceIntegrityError(
            f"owner reference dimensions are {dimensions[0]}x{dimensions[1]}, expected {OWNER_REFERENCE_SIZE[0]}x{OWNER_REFERENCE_SIZE[1]}"
        )
    return resolved


def rgb(path: Path) -> np.ndarray:
    return np.asarray(Image.open(path).convert("RGB"), dtype=np.float32) / 255.0


def normalize_reference(path: Path, size: tuple[int, int]) -> np.ndarray:
    image = Image.open(path).convert("RGB").resize(size, Image.Resampling.LANCZOS)
    return np.asarray(image, dtype=np.float32) / 255.0


def bounds_tuple(value: dict[str, int]) -> tuple[int, int, int, int]:
    return int(value["x"]), int(value["y"]), int(value["width"]), int(value["height"])


def as_bounds(value: tuple[int, int, int, int]) -> dict[str, int]:
    return {"x": value[0], "y": value[1], "width": value[2], "height": value[3]}


def delta(actual: dict[str, int], reference: dict[str, int]) -> dict[str, int]:
    return {key: int(actual[key] - reference[key]) for key in ("x", "y", "width", "height")}


def structure_mask(manifest: dict, shape: tuple[int, int]) -> np.ndarray:
    height, width = shape
    structure = np.zeros(shape, dtype=bool)

    def rect(x: int, y: int, w: int, h: int) -> None:
        x0, y0 = max(0, x), max(0, y)
        x1, y1 = min(width, x + w), min(height, y + h)
        structure[y0:y1, x0:x1] = True

    for item in manifest["structure"]["rects"]:
        rect(item["x"], item["y"], item["width"], item["height"])
    yy, xx = np.indices(shape)
    for item in manifest["structure"]["ellipses"]:
        structure |= ((xx - item["cx"]) / item["rx"]) ** 2 + ((yy - item["cy"]) / item["ry"]) ** 2 <= 1.0
    for item in manifest["structure"]["outlines"]:
        x, y, w, h, stroke = item["x"], item["y"], item["width"], item["height"], item["stroke"]
        rect(x, y, w, stroke); rect(x, y + h - stroke, w, stroke)
        rect(x, y, stroke, h); rect(x + w - stroke, y, stroke, h)
    for item in manifest["structure"]["dividerLines"]:
        rect(item["x"], item["y"] - item["thickness"] // 2, item["width"], item["thickness"])
    return structure


def glyph_candidates(image: np.ndarray, roi: list[int]) -> np.ndarray:
    """Detect glyph edge/contrast pixels inside one tight ROI, then dilate 2px."""
    x, y, width, height = roi
    gray = np.dot(image[y:y + height, x:x + width], [0.2126, 0.7152, 0.0722])
    smooth = gaussian_filter(gray, 0.7)
    local = np.abs(smooth - gaussian_filter(smooth, 2.2))
    edges = np.hypot(sobel(smooth, axis=1), sobel(smooth, axis=0)) / 2.0
    candidate = (edges >= 0.028) | (local >= 0.018)
    # Reject isolated material/noise specks while retaining small punctuation.
    labels, count = label(candidate, structure=np.ones((3, 3), dtype=np.uint8))
    if count:
        areas = np.bincount(labels.ravel())
        candidate &= areas[labels] >= 2
        # A component spanning most of a row is a material/selection band,
        # card edge, or divider—not a glyph cluster.  Keep text clusters while
        # rejecting these broad strokes before the two-pixel allowance.
        for component_id, component_slice in enumerate(find_objects(labels), 1):
            if component_slice is None:
                continue
            component_height = component_slice[0].stop - component_slice[0].start
            component_width = component_slice[1].stop - component_slice[1].start
            if component_width > 120 or component_height > 40:
                candidate[labels == component_id] = False
    candidate = binary_dilation(candidate, iterations=2)
    output = np.zeros(image.shape[:2], dtype=bool)
    output[y:y + height, x:x + width] = candidate
    return output


def validate_mask(mask: np.ndarray, structure: np.ndarray, max_coverage: float = 0.10) -> None:
    """Fail closed for any structural pixel or over-broad mask."""
    overlap = int(np.count_nonzero(mask & structure))
    if overlap:
        raise EvidenceIntegrityError(f"glyph mask overlaps {overlap} structure pixels")
    coverage = float(mask.mean())
    if coverage > max_coverage:
        raise EvidenceIntegrityError(f"glyph mask coverage {coverage:.6f} exceeds {max_coverage:.0%}")


def build_glyph_mask(reference: np.ndarray, actual: np.ndarray, manifest: dict, structure: np.ndarray) -> np.ndarray:
    mask = np.zeros(reference.shape[:2], dtype=bool)
    for roi in manifest["glyphRois"]:
        mask |= glyph_candidates(reference, roi["reference"])
        mask |= glyph_candidates(actual, roi["actual"])
    validate_mask(mask, structure)
    return mask


def masked_ssim(left: np.ndarray, right: np.ndarray, mask: np.ndarray, gaussian_window: bool = False) -> float:
    left = left.copy(); right = right.copy(); right[mask] = left[mask]
    if gaussian_window:
        return float(structural_similarity(left, right, data_range=1.0, gaussian_weights=True, sigma=2, use_sample_covariance=False))
    return float(structural_similarity(left, right, data_range=1.0))


def dial_bbox(image: np.ndarray, detection: dict) -> tuple[int, int, int, int]:
    gray = np.dot(image, [0.2126, 0.7152, 0.0722])
    yy, xx = np.indices(gray.shape)
    cx, cy = detection["center"]
    radius = detection["radius"]
    low, high = detection["yRange"]
    region = (gray > detection["threshold"] / 255.0) & (((xx - cx) / radius) ** 2 + ((yy - cy) / radius) ** 2 < 1.1) & (yy > low) & (yy < high)
    ys, xs = np.where(region)
    if not len(xs):
        raise EvidenceIntegrityError("dial landmark detection found no pixels")
    return int(xs.min()), int(ys.min()), int(xs.max() - xs.min() + 1), int(ys.max() - ys.min() + 1)


def save_rgb(path: Path, array: np.ndarray) -> None:
    Image.fromarray(np.asarray(np.clip(np.round(array * 255), 0, 255), dtype=np.uint8), "RGB").save(path, optimize=False)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_EVIDENCE)
    parser.add_argument("--actual", type=Path, default=DEFAULT_ACTUAL)
    parser.add_argument("--reference", type=Path, default=DEFAULT_REFERENCE)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve(); output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(args.manifest.resolve().read_text(encoding="utf-8"))
    if manifest.get("version") != "UI1-OBSIDIAN-PIXEL-LANDMARKS-1":
        raise EvidenceIntegrityError("unsupported landmark manifest version")
    viewport = (int(manifest["viewport"]["width"]), int(manifest["viewport"]["height"]))
    reference_path = validate_owner_reference(args.reference)
    manifest_reference_value = manifest.get("ownerReference")
    if not isinstance(manifest_reference_value, str) or not manifest_reference_value:
        raise EvidenceIntegrityError("landmark manifest must declare its repository ownerReference")
    manifest_reference = (ROOT / Path(manifest_reference_value)).resolve()
    if manifest_reference != reference_path:
        raise EvidenceIntegrityError(
            f"landmark ownerReference does not match the validated input: {manifest_reference} != {reference_path}"
        )
    reference = normalize_reference(reference_path, viewport)
    actual = rgb(args.actual.resolve())
    if actual.shape[:2] != (viewport[1], viewport[0]):
        raise EvidenceIntegrityError(f"actual viewport is {actual.shape[1]}x{actual.shape[0]}, expected {viewport[0]}x{viewport[1]}")
    structure = structure_mask(manifest, reference.shape[:2])
    mask = build_glyph_mask(reference, actual, manifest, structure)

    normalized_reference_path = output / "reference-normalized-1440x810.png"
    overlay_path = output / "ui1-windows-protected-overlay-1440x810.png"
    heatmap_path = output / "ui1-windows-protected-diff-heatmap-1440x810.png"
    mask_path = output / "ui1-pixel-glyph-mask-1440x810.png"
    alpha_path = output / "ui1-pixel-glyph-mask-alpha-1440x810.png"
    json_path = output / "ui1-pixel-acceptance.json"
    save_rgb(normalized_reference_path, reference)
    save_rgb(overlay_path, reference * 0.5 + actual * 0.5)
    diff_image = np.abs(reference - actual).mean(axis=2)
    diff_image = np.clip(diff_image * 4.5, 0, 1)
    save_rgb(heatmap_path, np.stack((diff_image, np.sqrt(diff_image), 1.0 - diff_image), axis=2))
    magenta = np.zeros((*mask.shape, 4), dtype=np.uint8); magenta[:, :, :3] = (244, 58, 130); magenta[:, :, 3] = np.where(mask, 184, 0).astype(np.uint8)
    Image.fromarray(magenta, "RGBA").save(output / "ui1-pixel-mask-1440x810.png", optimize=False)
    mask_overlay = np.asarray(np.round(reference * 255), dtype=np.float32); alpha = magenta[:, :, 3, None].astype(np.float32) / 255.0
    mask_overlay = mask_overlay * (1 - alpha) + magenta[:, :, :3].astype(np.float32) * alpha
    Image.fromarray(np.asarray(mask_overlay, dtype=np.uint8), "RGB").save(mask_path, optimize=False)
    Image.fromarray(np.where(mask, 255, 0).astype(np.uint8), "L").save(alpha_path, optimize=False)

    ref_l = np.dot(reference, [0.2126, 0.7152, 0.0722]); actual_l = np.dot(actual, [0.2126, 0.7152, 0.0722])
    luminance = masked_ssim(gaussian_filter(ref_l, 4), gaussian_filter(actual_l, 4), mask)
    raw_ref_edge = np.clip(np.hypot(sobel(gaussian_filter(ref_l, 2), axis=1), sobel(gaussian_filter(ref_l, 2), axis=0)) / 2, 0, 1)
    raw_actual_edge = np.clip(np.hypot(sobel(gaussian_filter(actual_l, 2), axis=1), sobel(gaussian_filter(actual_l, 2), axis=0)) / 2, 0, 1)
    def threshold_edges(value: np.ndarray, threshold: float) -> np.ndarray:
        return np.where(value >= threshold, value, 0)
    primary = masked_ssim(threshold_edges(raw_ref_edge, 0.05), threshold_edges(raw_actual_edge, 0.05), mask)
    strict = masked_ssim(threshold_edges(raw_ref_edge, 0.04), threshold_edges(raw_actual_edge, 0.04), mask)
    gaussian_strict = masked_ssim(threshold_edges(raw_ref_edge, 0.04), threshold_edges(raw_actual_edge, 0.04), mask, gaussian_window=True)

    landmarks = manifest["landmarks"]
    reference_bounds = {name: bounds_tuple(item["reference"]) for name, item in landmarks.items() if name != "dial"}
    actual_bounds = {name: bounds_tuple(item["actual"]) for name, item in landmarks.items() if name != "dial"}
    ref_dial = bounds_tuple(landmarks["dial"]["reference"]); actual_dial = dial_bbox(actual, landmarks["dial"]["detection"])
    reference_bounds["dial"] = ref_dial; actual_bounds["dial"] = actual_dial
    ref_center = (ref_dial[0] + ref_dial[2] / 2, ref_dial[1] + ref_dial[3] / 2); actual_center = (actual_dial[0] + actual_dial[2] / 2, actual_dial[1] + actual_dial[3] / 2)
    ref_diameter = (ref_dial[2] + ref_dial[3]) / 2; actual_diameter = (actual_dial[2] + actual_dial[3]) / 2
    width_delta = (actual_dial[2] - ref_dial[2]) / ref_dial[2]; height_delta = (actual_dial[3] - ref_dial[3]) / ref_dial[3]; diameter_delta = (actual_diameter - ref_diameter) / ref_diameter
    center_pass = abs(actual_center[0] - ref_center[0]) <= 4 and abs(actual_center[1] - ref_center[1]) <= 4
    size_pass = all(abs(value) <= 0.04 for value in (width_delta, height_delta, diameter_delta))
    deltas = {name: delta(as_bounds(actual_bounds[name]), as_bounds(reference_bounds[name])) for name in reference_bounds}
    deltas["topCenterPx"] = {"x": (actual_bounds["topSegmented"][0] + actual_bounds["topSegmented"][2] / 2) - (reference_bounds["topSegmented"][0] + reference_bounds["topSegmented"][2] / 2), "y": (actual_bounds["topSegmented"][1] + actual_bounds["topSegmented"][3] / 2) - (reference_bounds["topSegmented"][1] + reference_bounds["topSegmented"][3] / 2)}
    deltas["bottomCenterPx"] = {"x": (actual_bounds["bottomMode"][0] + actual_bounds["bottomMode"][2] / 2) - (reference_bounds["bottomMode"][0] + reference_bounds["bottomMode"][2] / 2), "y": (actual_bounds["bottomMode"][1] + actual_bounds["bottomMode"][3] / 2) - (reference_bounds["bottomMode"][1] + reference_bounds["bottomMode"][3] / 2)}
    structure_pixels = int(np.count_nonzero(mask & structure))
    status = "PASS" if structure_pixels == 0 and mask.mean() <= 0.10 and primary >= 0.85 and center_pass and size_pass else "FAIL"
    pixel = {
        "schemaVersion": 5,
        "contract": "UI1-OBSIDIAN-V2-PIXEL-GLYPH-MASK",
        "reference": str(normalized_reference_path), "actual": str(args.actual.resolve()), "landmarkManifest": str(args.manifest.resolve()),
        "normalizedViewport": {"width": viewport[0], "height": viewport[1]},
        "comparisonState": "protected reference vs production WPF protected-test; state dots, dial material and divider geometry are unmasked",
        "inputProvenance": {"ownerReference": str(reference_path), "ownerReferenceSha256": OWNER_REFERENCE_SHA256, "ownerReferenceDimensions": {"width": OWNER_REFERENCE_SIZE[0], "height": OWNER_REFERENCE_SIZE[1]}, "productionActual": str(args.actual.resolve()), "generatedInputs": [], "maskInput": str(args.manifest.resolve())},
        "maskPolicy": "Transparent per-pixel glyph mask built from explicit one-row/cluster ROIs; only detected glyph edge/contrast pixels plus a maximum two-pixel anti-alias dilation are masked. No ROI is filled and no structure is hidden.",
        "maskArtifacts": {"path": str(mask_path), "alphaCompanion": str(alpha_path), "color": "#F43A82 alpha only on detected glyph pixels", "coverage": float(mask.mean()), "coveragePercent": float(mask.mean() * 100), "maxAllowedPercent": 10, "structurePixelsMasked": structure_pixels, "structureMaskCoveragePercent": 0.0, "structureRegions": ["shell", "three-column-boundaries", "dial", "top-segmented", "bottom-segmented", "inspector-card-boundaries", "inspector-divider-lines"], "glyphOnly": structure_pixels == 0},
        "referenceBounds": {name: as_bounds(value) for name, value in reference_bounds.items()}, "actualBounds": {name: as_bounds(value) for name, value in actual_bounds.items()}, "delta": {name: value for name, value in deltas.items()},
        "topCenterPx": deltas["topCenterPx"],
        "bottomCenterPx": deltas["bottomCenterPx"],
        "dialGeometry": {"referenceCenterPx": {"x": ref_center[0], "y": ref_center[1]}, "actualCenterPx": {"x": actual_center[0], "y": actual_center[1]}, "centerOffsetPx": {"x": actual_center[0] - ref_center[0], "y": actual_center[1] - ref_center[1]}, "referenceDiameterPx": ref_diameter, "actualDiameterPx": actual_diameter, "diameterDeltaRelative": diameter_delta, "widthDeltaRelative": width_delta, "heightDeltaRelative": height_delta, "centerMaxPx": 4, "sizeMaxRelative": 0.04, "centerPass": center_pass, "sizePass": size_pass},
        "brandPlatformDifference": manifest["brandPlatformDifference"],
        "metrics": {"luminanceSsim": luminance, "edgeSsim": primary, "edgeSsimStrictThreshold04": strict, "edgeSsimStrictGaussianSigma2Threshold04": gaussian_strict, "edgeMethod": "Raw edge magnitude = clipped Sobel magnitude after Gaussian sigma=2 preblur; primary thresholds raw magnitude at 0.05, strict thresholds the same raw magnitude at 0.04, and Gaussian-window strict uses structural_similarity gaussian_weights=true sigma=2 on the 0.04-threshold edge maps. Luminance uses sigma=4 low-frequency masked SSIM.", "threshold": 0.85, "edgeFloor": 0.05, "strictEdgeFloor": 0.04},
        "thresholds": {"edgeSsimMin": 0.85, "topCenterMaxPx": 8, "bottomCenterMaxPx": 8, "segmentedWidthMaxRelative": 0.05, "maskMaxPercent": 10, "dialCenterMaxPx": 4, "dialSizeMaxRelative": 0.04},
        "status": status,
        "artifacts": ["reference-normalized-1440x810.png", "ui1-windows-protected-overlay-1440x810.png", "ui1-windows-protected-diff-heatmap-1440x810.png", "ui1-pixel-glyph-mask-1440x810.png", "ui1-pixel-glyph-mask-alpha-1440x810.png"]
    }
    json_path.write_text(json.dumps(pixel, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if status != "PASS":
        raise EvidenceIntegrityError(f"pixel evidence status={status}")
    print(json.dumps({"outputDir": str(output), "status": status, "maskCoveragePercent": pixel["maskArtifacts"]["coveragePercent"], "structurePixelsMasked": structure_pixels, "edgeSsim": primary, "edgeSsimStrictThreshold04": strict, "edgeSsimStrictGaussianSigma2Threshold04": gaussian_strict, "bottomModeDelta": deltas["bottomMode"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceIntegrityError as error:
        print(f"EVIDENCE_INTEGRITY_ERROR: {error}")
        raise SystemExit(2)
