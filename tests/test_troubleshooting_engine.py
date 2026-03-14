from app.analysis.troubleshooting_engine import TroubleshootingEngine


def test_troubleshoot_auto_default_and_specific_route_mix(standalone_config):
    engine = TroubleshootingEngine()

    result = engine.analyze_traffic(
        config=standalone_config,
        scope_name="vsys1",
        source_zone=None,
        destination_zone=None,
        source_ip="4.2.2.2",
        destination_ip="10.0.0.70",
        application="ssh",
        protocol=None,
        port=None,
    )

    assert result["source_zone"] == "Internet"
    assert result["destination_zone"] == "Azure-vpn"
    assert result["source_zone_resolution"]["matched_prefix"] == "0.0.0.0/0"
    assert result["destination_zone_resolution"]["matched_prefix"] == "10.0.0.64/26"
    assert result["action"] == "deny"