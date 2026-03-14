from app.analysis.route_lookup import RouteLookup


def test_route_lookup_default_route_on_standalone(standalone_config):
    scope = next(scope for scope in standalone_config.scopes if scope.name == "vsys1")
    lookup = RouteLookup(scope)

    result = lookup.lookup("8.8.8.8")

    assert result["status"] == "resolved"
    assert result["method"] == "default_route"
    assert result["matched_prefix"] == "0.0.0.0/0"


def test_route_lookup_specific_static_route_on_standalone(standalone_config):
    scope = next(scope for scope in standalone_config.scopes if scope.name == "vsys1")
    lookup = RouteLookup(scope)

    result = lookup.lookup("10.0.0.10")

    assert result["status"] == "resolved"
    assert result["method"] == "route_lookup"
    assert result["matched_prefix"] == "10.0.0.0/26"