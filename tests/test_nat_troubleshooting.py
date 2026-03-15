"""
Focused integration tests for NAT evaluation inside TroubleshootingEngine.

These tests verify that:
- When no nat_rules are passed, existing behavior is fully unchanged.
- When destination NAT applies, security rule evaluation uses the
  translated destination IP.
- When source NAT applies, security rule evaluation uses the translated
  source IP.
- When a NAT rule is present but does not match the flow, evaluation
  falls back to the original IPs.
"""
from app.analysis.troubleshooting_engine import TroubleshootingEngine
from app.models.nat_model import (
    DestinationTranslation,
    NatRule,
    SourceTranslation,
    SourceTranslationType,
)
from app.models.normalized_firewall_model import (
    FirewallConfig,
    Scope,
    ScopeType,
    SecurityRule,
    Vendor,
)


# ---------------------------------------------------------------------------
# Minimal in-memory config helpers
# ---------------------------------------------------------------------------

def _make_config(security_rules: list) -> FirewallConfig:
    """
    Build a minimal FirewallConfig with a single 'test' scope containing
    the provided security rules. Zones 'inside' and 'outside' are declared
    so zone validation passes when those zones are passed explicitly.
    """
    scope = Scope(
        name="test",
        scope_type=ScopeType.STANDALONE,
        zones=["inside", "outside"],
        security_rules=security_rules,
    )
    return FirewallConfig(vendor=Vendor.PALO_ALTO, scopes=[scope])


def _allow_rule(name: str, src: str, dst: str, service: str = "any") -> SecurityRule:
    return SecurityRule(
        name=name,
        from_zones=["inside"],
        to_zones=["outside"],
        source_addresses=[src],
        destination_addresses=[dst],
        applications=["any"],
        services=[service],
        action="allow",
    )


def _deny_rule(name: str, src: str, dst: str) -> SecurityRule:
    return SecurityRule(
        name=name,
        from_zones=["inside"],
        to_zones=["outside"],
        source_addresses=[src],
        destination_addresses=[dst],
        applications=["any"],
        services=["any"],
        action="deny",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_nat_rules_nat_section_applied_is_false():
    """
    When no nat_rules are passed, the nat section must report applied=False
    and existing rule evaluation behavior must be unchanged.
    """
    config = _make_config([_allow_rule("allow-all", "any", "any")])
    engine = TroubleshootingEngine()

    result = engine.analyze_traffic(
        config=config,
        scope_name="test",
        source_zone="inside",
        destination_zone="outside",
        source_ip="10.0.0.1",
        destination_ip="8.8.8.8",
        application="ssl",
        nat_rules=None,
    )

    assert result["result"] == "matched"
    assert result["action"] == "allow"
    assert result["nat"]["applied"] is False


def test_destination_nat_translates_ip_for_rule_evaluation():
    """
    When a destination NAT rule translates 8.8.8.8 -> 192.168.1.100, the
    security rule that matches destination 192.168.1.100 must be hit.
    Without NAT the rule would not match (original dst 8.8.8.8 != 192.168.1.100).
    """
    # Security rule matches only the translated destination
    config = _make_config([_allow_rule("allow-translated-dst", "any", "192.168.1.100")])

    nat_rule = NatRule(
        name="dst-nat",
        enabled=True,
        from_zones=["inside"],
        to_zones=["outside"],
        source_addresses=["any"],
        destination_addresses=["8.8.8.8"],
        services=["any"],
        destination_translation=DestinationTranslation(translated_address="192.168.1.100"),
        rule_order=1,
    )

    engine = TroubleshootingEngine()
    result = engine.analyze_traffic(
        config=config,
        scope_name="test",
        source_zone="inside",
        destination_zone="outside",
        source_ip="10.0.0.1",
        destination_ip="8.8.8.8",
        application="ssl",
        nat_rules=[nat_rule],
    )

    assert result["nat"]["applied"] is True
    assert result["nat"]["matched_rule"] == "dst-nat"
    assert result["nat"]["destination_before"] == "8.8.8.8"
    assert result["nat"]["destination_after"] == "192.168.1.100"
    # Original IPs preserved in top-level output
    assert result["destination_ip"] == "8.8.8.8"
    assert result["result"] == "matched"
    assert result["rule_name"] == "allow-translated-dst"


def test_destination_nat_no_match_uses_original_ip():
    """
    When a NAT rule exists but does not match the flow, the security rule
    must be evaluated against the original destination IP.
    """
    # Security rule matches the original destination
    config = _make_config([_allow_rule("allow-original-dst", "any", "8.8.8.8")])

    # NAT rule matches a different destination — will not fire
    nat_rule = NatRule(
        name="dst-nat-other",
        enabled=True,
        from_zones=["inside"],
        to_zones=["outside"],
        source_addresses=["any"],
        destination_addresses=["9.9.9.9"],
        services=["any"],
        destination_translation=DestinationTranslation(translated_address="192.168.1.100"),
        rule_order=1,
    )

    engine = TroubleshootingEngine()
    result = engine.analyze_traffic(
        config=config,
        scope_name="test",
        source_zone="inside",
        destination_zone="outside",
        source_ip="10.0.0.1",
        destination_ip="8.8.8.8",
        application="ssl",
        nat_rules=[nat_rule],
    )

    assert result["nat"]["applied"] is False
    assert result["nat"]["matched_rule"] is None
    assert result["result"] == "matched"
    assert result["rule_name"] == "allow-original-dst"


def test_source_nat_translates_source_for_rule_evaluation():
    """
    When a source NAT rule translates 10.0.0.1 -> 203.0.113.1, the security
    rule that matches source 203.0.113.1 must be hit.
    """
    config = _make_config([_allow_rule("allow-translated-src", "203.0.113.1", "any")])

    nat_rule = NatRule(
        name="src-nat",
        enabled=True,
        from_zones=["inside"],
        to_zones=["outside"],
        source_addresses=["10.0.0.1"],
        destination_addresses=["any"],
        services=["any"],
        source_translation=SourceTranslation(
            type=SourceTranslationType.STATIC_IP,
            translated_addresses=["203.0.113.1"],
        ),
        rule_order=1,
    )

    engine = TroubleshootingEngine()
    result = engine.analyze_traffic(
        config=config,
        scope_name="test",
        source_zone="inside",
        destination_zone="outside",
        source_ip="10.0.0.1",
        destination_ip="8.8.8.8",
        application="ssl",
        nat_rules=[nat_rule],
    )

    assert result["nat"]["applied"] is True
    assert result["nat"]["matched_rule"] == "src-nat"
    assert result["nat"]["source_before"] == "10.0.0.1"
    assert result["nat"]["source_after"] == "203.0.113.1"
    # Original source IP preserved in top-level output
    assert result["source_ip"] == "10.0.0.1"
    assert result["result"] == "matched"
    assert result["rule_name"] == "allow-translated-src"


def test_existing_troubleshoot_test_unaffected(standalone_config):
    """
    Regression test: the existing troubleshooting behavior (no nat_rules)
    is fully unchanged. Mirrors test_troubleshoot_auto_default_and_specific_route_mix.
    """
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
    assert result["nat"]["applied"] is False
