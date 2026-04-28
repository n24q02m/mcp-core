"""Schema validation for matrix.yaml. Locks the 16-config taxonomy.

History:
- 2026-04-27: 16 → 15 by reclassifying notion-oauth out of T2 (Notion app
  dashboard does not accept dynamic loopback callbacks, no DCR support).
- 2026-04-28: 15 → 16 by adding notion-oauth back as a new ``t3-staging``
  tier. The new tier hits a stable staging URL (callback prod-registered
  in the Notion app dashboard) instead of a local container, satisfying
  ``feedback_no_out_of_band_test_setup`` while still preserving E2E
  coverage. See ``feedback_notion_oauth_staging_flow`` for the release
  cascade rule (beta CD → deploy staging → E2E → stable CD).
"""

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
    t3_staging = [c for c in data["configs"] if c["tier"] == "t3-staging"]
    # 2026-04-28 final: 5 t0-only + 6 t2-non-interaction + 4 t2-interaction
    # + 1 t3-staging (notion-oauth via beta CD → staging deploy → E2E gate).
    assert len(t0_only) == 5
    assert len(t2_non) == 6
    assert len(t2_int) == 4
    assert len(t3_staging) == 1


def test_matrix_auth_modes_in_documented_superset() -> None:
    """Configs span the documented ``{none, oauth, relay}`` superset.

    ``oauth`` re-enters the matrix on 2026-04-28 with the t3-staging
    notion-oauth config; the test now asserts the full superset rather
    than the post-reclassification subset.
    """
    data = _load()
    auths = {c["auth"] for c in data["configs"]}
    assert auths <= {"none", "oauth", "relay"}, (
        f"unexpected auth modes outside documented superset: {auths}"
    )
    assert "oauth" in auths, "notion-oauth t3-staging missing from matrix"


def test_notion_oauth_is_t3_staging() -> None:
    """notion-oauth is the sole t3-staging tier config and uses staging_url."""
    data = _load()
    notion = [c for c in data["configs"] if c["id"] == "notion-oauth"]
    assert len(notion) == 1, "notion-oauth must be present as the t3-staging gate"
    cfg = notion[0]
    assert cfg["tier"] == "t3-staging"
    assert cfg["auth"] == "oauth"
    assert cfg.get("deployment") == ["staging"], (
        "notion-oauth deployment must be exactly [staging]"
    )
    assert "staging_url" in cfg and cfg["staging_url"].startswith("https://"), (
        "notion-oauth must declare https staging_url"
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
        # t3-staging hits a deployed instance; skret values are injected by
        # the staging deployment's own runtime (not by the local driver),
        # so the matrix entry has no skret_namespace.
        if c["tier"] == "t3-staging":
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
