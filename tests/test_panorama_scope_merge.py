from app.analysis.troubleshooting_engine import TroubleshootingEngine


def test_panorama_effective_scope_has_forwarding_data(panorama_config):
    engine = TroubleshootingEngine()
    scope = engine._find_effective_scope(panorama_config, "Apex WH")

    assert scope is not None
    assert len(scope.interfaces) > 0
    assert len(scope.routes) > 0
    assert len(scope.zone_bindings) > 0