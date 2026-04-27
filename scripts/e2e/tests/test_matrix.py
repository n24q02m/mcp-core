"""Schema validation for matrix.yaml. Locks the 16-config 3-axis taxonomy."""

from pathlib import Path

import yaml

MATRIX_PATH = Path(__file__).parent.parent / "matrix.yaml"


def _load() -> dict:
    return yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))


def test_matrix_has_16_configs() -> None:
    data = _load()
    assert len(data["configs"]) == 16


def test_matrix_tier_distribution() -> None:
    data = _load()
    t0_only = [c for c in data["configs"] if c["tier"] == "t0-only"]
    t2_non = [c for c in data["configs"] if c["tier"] == "t2-non-interaction"]
    t2_int = [c for c in data["configs"] if c["tier"] == "t2-interaction"]
    # 2026-04-27 evolution:
    # * Initially wet-full + mnemo-full were tagged t2-interaction with a
    #   "Click GDrive device-code link" user gate.
    # * Brief reclassification to t2-non-interaction when multi-user mode
    #   was found to skip the GDrive trigger entirely.
    # * Now restored to t2-interaction after wet-mcp 52ec8da + mnemo-mcp
    #   b0b66e4 added per-sub GDrive triggers in the multi-user branch.
    # Final: 5 t0-only, 6 t2-non-interaction, 5 t2-interaction.
    assert len(t0_only) == 5
    assert len(t2_non) == 6
    assert len(t2_int) == 5


def test_matrix_auth_modes_only_three() -> None:
    data = _load()
    auths = {c["auth"] for c in data["configs"]}
    assert auths.issubset({"none", "oauth", "relay"}), f"unexpected auth modes: {auths}"


def test_matrix_ids_unique() -> None:
    data = _load()
    ids = [c["id"] for c in data["configs"]]
    assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"


def test_t2_configs_have_skret_namespace_when_auth_present() -> None:
    data = _load()
    for c in data["configs"]:
        if c["tier"] == "t0-only":
            continue
        if c["auth"] == "none":
            continue
        assert "skret_namespace" in c, f"{c['id']} missing skret_namespace"
        assert c["skret_namespace"].startswith("/"), f"{c['id']} ns must start with /"


def test_t2_interaction_configs_have_user_gate() -> None:
    data = _load()
    for c in data["configs"]:
        if c["tier"] != "t2-interaction":
            continue
        assert "user_gate" in c, f"{c['id']} missing user_gate"
        assert c["user_gate"], f"{c['id']} user_gate empty"
