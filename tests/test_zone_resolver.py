from app.analysis.zone_resolver import ZoneResolver


def test_zone_resolver_uses_default_route_for_internet_ip(standalone_config):
    scope = next(scope for scope in standalone_config.scopes if scope.name == "vsys1")
    resolver = ZoneResolver(scope)

    result = resolver.resolve("4.2.2.2")

    assert result["status"] == "resolved"
    assert result["zone"] == "Internet"
    assert result["matched_prefix"] == "0.0.0.0/0"


def test_zone_resolver_uses_specific_route_for_azure_ip(standalone_config):
    scope = next(scope for scope in standalone_config.scopes if scope.name == "vsys1")
    resolver = ZoneResolver(scope)

    result = resolver.resolve("10.0.0.70")

    assert result["status"] == "resolved"
    assert result["zone"] == "Azure-vpn"
    assert result["matched_prefix"] == "10.0.0.64/26"