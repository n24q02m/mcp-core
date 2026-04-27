"""Schema validation for matrix.yaml. Locks the 15-config 3-axis taxonomy.

Reduced from 16 → 15 on 2026-04-27 by reclassifying notion-oauth out of T2:
the upstream Notion OAuth app accepts only pre-registered redirect URIs and
does not support DCR or loopback wildcards, which would force E2E to bake in
out-of-band dashboard registration per ``feedback_no_out_of_band_test_setup``.
notion-oauth is verified post-deploy via manual smoke against the production
instance instead of the local Docker matrix.
"""

from pathlib import Path

import yaml

MATRIX_PATH = Path(__file__).parent.parent / "matrix.yaml"


def _load() -> dict:
    return yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))


def test_matrix_has_15_configs() -> None:
    data = _load()
    assert len(data["configs"]) == 15


def test_matrix_tier_distribution() -> None:
    data = _load()
    t0_only = [c for c in data["configs"] if c["tier"] == "t0-only"]
    t2_non = [c for c in data["configs"] if c["tier"] == "t2-non-interaction"]
    t2_int = [c for c in data["configs"] if c["tier"] == "t2-interaction"]
    # 2026-04-27 final: 5 t0-only + 6 t2-non-interaction + 4 t2-interaction.
    # notion-oauth removed (out-of-band setup, see module docstring).
    assert len(t0_only) == 5
    assert len(t2_non) == 6
    assert len(t2_int) == 4


def test_matrix_auth_modes_only_relay_and_none_after_reclassification() -> None:
    """``oauth`` drops out of the matrix once notion-oauth is reclassified.

    Kept the original ``{none, oauth, relay}`` superset valid in the
    matrix.yaml comment (legal axis values), but the actual configs in
    use post-reclassification only span ``none`` + ``relay``. Test asserts
    no surprise re-introduction of ``oauth`` in matrix.yaml.
    """
    data = _load()
    auths = {c["auth"] for c in data["configs"]}
    assert auths == {"none", "relay"}, (
        f"unexpected auth modes after reclassification: {auths}"
    )


def test_matrix_does_not_include_notion_oauth() -> None:
    data = _load()
    ids = [c["id"] for c in data["configs"]]
    assert "notion-oauth" not in ids, (
        "notion-oauth must stay reclassified out of T2 — see module docstring"
    )


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
