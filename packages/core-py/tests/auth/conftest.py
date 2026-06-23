import pytest


@pytest.fixture(autouse=True)
def _stub_provider_catalog(monkeypatch):
    """Keep relay-form rendering tests network-free.

    The model-chain catalog builder (``_catalog_models_for_task``) fetches the
    live Jina model list over the network, so stub it to empty by default for
    every auth test. Tests that exercise the provider-catalog merge override this
    with their own ``monkeypatch.setattr`` (applied after this fixture, so it
    wins).
    """
    import mcp_core.llm.provider_catalog as pc

    monkeypatch.setattr(pc, "provider_catalog_models", lambda task: [])
