from app.models.normalized_firewall_model import ScopeType


def test_standalone_parser_builds_forwarding_data(standalone_config):
    assert standalone_config.vendor.value == "palo_alto"
    assert standalone_config.config_type == "standalone"
    assert len(standalone_config.scopes) >= 1

    scope = standalone_config.scopes[0]
    assert len(scope.zones) > 0
    assert len(scope.interfaces) > 0
    assert len(scope.zone_bindings) > 0
    assert len(scope.virtual_routers) > 0
    assert len(scope.routes) > 0


def test_panorama_parser_builds_multiple_scope_types(panorama_config):
    scope_types = {scope.scope_type for scope in panorama_config.scopes}

    assert ScopeType.DEVICE_GROUP in scope_types
    assert ScopeType.TEMPLATE in scope_types
    assert ScopeType.TEMPLATE_STACK in scope_types