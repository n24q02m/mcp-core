"""Schema validation for matrix.yaml. Locks the config taxonomy.

History:
- 2026-04-27: 16 → 15 by reclassifying notion-oauth out of T2 (Notion app
  dashboard does not accept dynamic loopback callbacks, no DCR support).
- 2026-04-28: 15 → 16 by adding notion-oauth back as a new ``t3-staging``
  tier. The new tier hits a stable staging URL (callback prod-registered
  in the Notion app dashboard) instead of a local container, satisfying
  ``feedback_no_out_of_band_test_setup`` while still preserving E2E
  coverage. See ``feedback_notion_oauth_staging_flow`` for the release
  cascade rule (beta CD → deploy staging → E2E → stable CD).
- 2026-04-30: 16 → 21 by adding 5 stdio-direct configs (Task 6 of the
  multi-mode stdio/HTTP architecture refactor). stdio-direct configs
  carry ``type: stdio-direct`` and run on a parallel axis to the
  ``tier`` taxonomy — they drive Python plugins via the MCP SDK
  ``stdio_client`` instead of HTTP, verifying that the stdio entry
  point loads tools without an HTTP daemon. They have no ``tier`` /
  ``auth`` / ``skret_namespace`` field (tier-less + no upstream
  identity surface required).
- 2026-05-02: 21 → 32 per spec ``2026-05-01-stdio-pure-http-multiuser.md``
  §5.5: dropped the ``deployment: [local, remote]`` matrix axis from T2
  configs (HTTP is always multi-user, single deployment shape) and added
  9 ``<plugin>-stdio`` configs (skret-pulled env + uvx + tools/call) plus
  2 ``multi-session-{stdio,http}`` runtime-invariant configs. Introduces
  the ``auth: env`` value (pure env-var stdio) on top of the original
  ``{none, oauth, relay}`` superset.
"""

from pathlib import Path

import yaml

MATRIX_PATH = Path(__file__).parent.parent / "matrix.yaml"

STDIO_DIRECT_IDS = {
    "wet-stdio-direct",
    "mnemo-stdio-direct",
    "crg-stdio-direct",
    "imagine-stdio-direct",
    "telegram-stdio-direct",
}


def _load() -> dict:
    return yaml.safe_load(MATRIX_PATH.read_text(encoding="utf-8"))


def _tiered(configs: list[dict]) -> list[dict]:
    """Return only tier-axis configs (drops stdio-direct parallel axis)."""
    return [c for c in configs if c.get("type") != "stdio-direct"]


def test_matrix_has_32_configs() -> None:
    data = _load()
    # 16 tier-axis pre-2026-05-02
    #   (5 t0-only + 6 t2-non-interaction + 4 t2-interaction + 1 t3-staging)
    # + 5 stdio-direct (parallel axis, 2026-04-30)
    # + 9 stdio configs (8 plugin + 1 negative, 2026-05-02 §5.5.3)
    # + 2 multi-session invariants (2026-05-02 §5.5.3)
    # = 32.
    assert len(data["configs"]) == 31


def test_matrix_tier_distribution() -> None:
    data = _load()
    tiered = _tiered(data["configs"])
    t0_only = [c for c in tiered if c["tier"] == "t0-only"]
    t2_non = [c for c in tiered if c["tier"] == "t2-non-interaction"]
    t2_int = [c for c in tiered if c["tier"] == "t2-interaction"]
    t3_staging = [c for c in tiered if c["tier"] == "t3-staging"]
    # 2026-05-02 final: 5 t0-only + (6 relay/none non-int + 9 stdio +
    # 2 multi-session = 17 t2-non-interaction) + 4 t2-interaction
    # + 1 t3-staging.
    assert len(t0_only) == 5
    assert len(t2_non) == 16
    assert len(t2_int) == 4
    assert len(t3_staging) == 1


def test_matrix_auth_modes_in_documented_superset() -> None:
    """Configs span the documented ``{none, oauth, relay, env}`` superset.

    ``oauth`` re-enters the matrix on 2026-04-28 with the t3-staging
    notion-oauth config. ``env`` joins on 2026-05-02 for stdio-pure
    configs that pull credentials from skret (or run cred-less) and
    spawn ``uvx <plugin>`` directly. stdio-direct configs are on a
    parallel axis and have no ``auth`` field (no upstream identity).
    """
    data = _load()
    auths = {c["auth"] for c in _tiered(data["configs"])}
    assert auths <= {"none", "oauth", "relay", "env"}, (
        f"unexpected auth modes outside documented superset: {auths}"
    )
    assert "oauth" in auths, "notion-oauth t3-staging missing from matrix"
    assert "env" in auths, "stdio-pure env configs missing from matrix"


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
    # Multi-plugin invariant configs (``repo: all``) iterate every plugin
    # at runtime and resolve each one's skret namespace from the per-plugin
    # entry. The aggregate config itself has no single namespace to declare.
    multi_plugin_ids = {
        "stdio-no-env-negative",
        "multi-session-stdio",
        "multi-session-http",
    }
    for c in _tiered(data["configs"]):
        if c["tier"] == "t0-only":
            continue
        if c["auth"] == "none":
            continue
        # t3-staging hits a deployed instance; skret values are injected by
        # the staging deployment's own runtime (not by the local driver),
        # so the matrix entry has no skret_namespace.
        if c["tier"] == "t3-staging":
            continue
        if c["id"] in multi_plugin_ids:
            continue
        assert "skret_namespace" in c, f"{c['id']} missing skret_namespace"
        assert c["skret_namespace"].startswith("/"), f"{c['id']} ns must start with /"


def test_no_deployment_axis_on_t2_configs() -> None:
    """Per spec ``2026-05-01-stdio-pure-http-multiuser.md`` §5.5.2.

    HTTP mode is always multi-user (single deployment shape), so the
    legacy ``deployment: [local, remote]`` matrix axis is dropped from
    every T2 config. ``t3-staging`` keeps ``deployment: [staging]`` as
    its only allowed value (notion-oauth special flow).
    """
    data = _load()
    for c in _tiered(data["configs"]):
        if c["tier"] == "t3-staging":
            continue
        if c["tier"] == "t0-only":
            continue
        assert "deployment" not in c, (
            f"{c['id']} (tier={c['tier']}) must not declare a "
            "deployment axis after 2026-05-02 spec"
        )


def test_stdio_pure_configs_present() -> None:
    """8 plugin stdio configs + 1 negative + 2 multi-session = 11 entries
    added 2026-05-02 per spec §5.5.3."""
    data = _load()
    expected = {
        "notion-stdio",
        "email-stdio-gmail",
        "telegram-stdio-bot",
        "wet-stdio",
        "mnemo-stdio",
        "crg-stdio",
        "imagine-stdio",
        "godot-stdio",
        "stdio-no-env-negative",
        "multi-session-stdio",
        "multi-session-http",
    }
    actual = {c["id"] for c in data["configs"]}
    missing = expected - actual
    assert not missing, f"stdio-pure configs missing from matrix: {missing}"


def test_t2_interaction_configs_have_user_gate() -> None:
    data = _load()
    for c in _tiered(data["configs"]):
        if c["tier"] != "t2-interaction":
            continue
        assert "user_gate" in c, f"{c['id']} missing user_gate"
        assert c["user_gate"], f"{c['id']} user_gate empty"


def test_stdio_direct_configs_present_with_required_fields() -> None:
    """5 stdio-direct configs (wet/mnemo/crg/imagine/telegram), each with
    cmd/env/expected_tools_min and no tier/auth (parallel axis)."""
    data = _load()
    stdio_configs = [c for c in data["configs"] if c.get("type") == "stdio-direct"]
    assert {c["id"] for c in stdio_configs} == STDIO_DIRECT_IDS
    for c in stdio_configs:
        assert isinstance(c.get("cmd"), list) and len(c["cmd"]) >= 1, (
            f"{c['id']} cmd must be a non-empty list"
        )
        assert c["cmd"][0] == "uvx", (
            f"{c['id']} cmd[0] must be 'uvx' (PyPI uvx-installable plugin)"
        )
        assert c.get("env", {}).get("MCP_TRANSPORT") == "stdio", (
            f"{c['id']} env must set MCP_TRANSPORT=stdio"
        )
        assert (
            isinstance(c.get("expected_tools_min"), int)
            and c["expected_tools_min"] >= 1
        ), f"{c['id']} expected_tools_min must be a positive int"
        # stdio-direct sits on a parallel axis: no tier / no auth.
        assert "tier" not in c, f"{c['id']} stdio-direct must not declare tier"
        assert "auth" not in c, f"{c['id']} stdio-direct must not declare auth"
