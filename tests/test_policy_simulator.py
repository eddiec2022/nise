from app.analysis.troubleshooting_engine import TroubleshootingEngine


def test_application_group_expansion_allows_ssl_match(panorama_config):
    engine = TroubleshootingEngine()

    result = engine.analyze_traffic(
        config=panorama_config,
        scope_name="Apex WH",
        source_zone=None,
        destination_zone=None,
        source_ip="172.16.90.10",
        destination_ip="8.8.8.8",
        application="ssl",
        protocol=None,
        port=None,
    )

    assert result["result"] == "matched"
    assert result["action"] == "allow"
    assert result["rule_name"] == "Streaming Media Web"