from collections import defaultdict
from typing import Dict, List

from app.models.normalized_firewall_model import (
    AddressObject,
    FirewallConfig,
    Finding,
    FindingCode,
    Scope,
    SecurityRule,
    Severity,
)


class SecurityAnalyzer:
    def analyze(self, config: FirewallConfig) -> List[Finding]:
        findings: List[Finding] = []

        for scope in config.scopes:
            findings.extend(self._check_duplicate_address_objects(scope))
            findings.extend(self._check_shadow_rules(scope))

            for rule in scope.security_rules:
                findings.extend(self._analyze_rule(scope, rule, config))

        return findings

    def _analyze_rule(self, scope: Scope, rule: SecurityRule, config: FirewallConfig) -> List[Finding]:
        findings: List[Finding] = []

        findings.extend(self._check_disabled_rule(scope, rule))

        if rule.disabled or rule.action.lower() != "allow":
            return findings

        findings.extend(self._check_opr(scope, rule))
        findings.extend(self._check_missing_session_end_logging(scope, rule))
        findings.extend(self._check_missing_security_profiles(scope, rule))
        findings.extend(self._check_missing_log_forwarding(scope, rule, config))
        findings.extend(self._check_missing_description(scope, rule))

        return findings

    def _check_opr(self, scope: Scope, rule: SecurityRule) -> List[Finding]:
        findings: List[Finding] = []

        any_count = 0

        if "any" in rule.source_addresses:
            any_count += 1
        if "any" in rule.destination_addresses:
            any_count += 1
        if "any" in rule.services:
            any_count += 1
        if "any" in rule.applications:
            any_count += 1

        if any_count >= 2:
            if any_count == 4:
                severity = Severity.CRITICAL
                minutes = 30
            elif any_count == 3:
                severity = Severity.HIGH
                minutes = 20
            else:
                severity = Severity.MEDIUM
                minutes = 15

            findings.append(
                Finding(
                    finding_code=FindingCode.OPR,
                    severity=severity,
                    scope_name=scope.name,
                    rule_name=rule.name,
                    issue="Overly permissive rule detected",
                    recommendation="Restrict source, destination, service, and/or application scope.",
                    estimated_minutes_to_resolve=minutes,
                    details={
                        "any_count": any_count,
                        "source_addresses": rule.source_addresses,
                        "destination_addresses": rule.destination_addresses,
                        "services": rule.services,
                        "applications": rule.applications,
                    },
                )
            )

        return findings

    def _check_missing_session_end_logging(self, scope: Scope, rule: SecurityRule) -> List[Finding]:
        if not rule.log_end:
            return [
                Finding(
                    finding_code=FindingCode.MSEL,
                    severity=Severity.MEDIUM,
                    scope_name=scope.name,
                    rule_name=rule.name,
                    issue="Session-end logging is disabled",
                    recommendation="Enable log at session end for improved auditability and troubleshooting.",
                    estimated_minutes_to_resolve=10,
                    details={"log_end": rule.log_end},
                )
            ]
        return []

    def _check_missing_security_profiles(self, scope: Scope, rule: SecurityRule) -> List[Finding]:
        has_profile_group = bool(rule.profile_group)
        has_individual_profiles = any(
            [
                rule.profile_antivirus,
                rule.profile_antispyware,
                rule.profile_vulnerability,
                rule.profile_url_filtering,
                rule.profile_file_blocking,
                rule.profile_wildfire_analysis,
            ]
        )

        if not has_profile_group and not has_individual_profiles:
            return [
                Finding(
                    finding_code=FindingCode.MSP,
                    severity=Severity.HIGH,
                    scope_name=scope.name,
                    rule_name=rule.name,
                    issue="No security profile group or individual security profiles applied",
                    recommendation="Apply an approved security profile group or the required individual security profiles.",
                    estimated_minutes_to_resolve=15,
                    details={
                        "profile_group": rule.profile_group,
                        "has_individual_profiles": has_individual_profiles,
                    },
                )
            ]
        return []

    def _check_missing_log_forwarding(self, scope: Scope, rule: SecurityRule, config: FirewallConfig) -> List[Finding]:
        if config.config_type != "panorama":
            return []

        if not rule.log_setting:
            return [
                Finding(
                    finding_code=FindingCode.MLF,
                    severity=Severity.MEDIUM,
                    scope_name=scope.name,
                    rule_name=rule.name,
                    issue="No log forwarding profile configured",
                    recommendation="Apply the approved Panorama log forwarding profile.",
                    estimated_minutes_to_resolve=10,
                    details={"log_setting": rule.log_setting},
                )
            ]
        return []

    def _check_missing_description(self, scope: Scope, rule: SecurityRule) -> List[Finding]:
        if not rule.description or not rule.description.strip():
            return [
                Finding(
                    finding_code=FindingCode.MDR,
                    severity=Severity.LOW,
                    scope_name=scope.name,
                    rule_name=rule.name,
                    issue="Rule description is missing",
                    recommendation="Add a meaningful rule description to improve maintainability.",
                    estimated_minutes_to_resolve=5,
                    details={},
                )
            ]
        return []

    def _check_disabled_rule(self, scope: Scope, rule: SecurityRule) -> List[Finding]:
        if rule.disabled:
            return [
                Finding(
                    finding_code=FindingCode.DR,
                    severity=Severity.LOW,
                    scope_name=scope.name,
                    rule_name=rule.name,
                    issue="Rule is disabled",
                    recommendation="Review whether this disabled rule is still needed or should be removed.",
                    estimated_minutes_to_resolve=5,
                    details={},
                )
            ]
        return []

    def _check_duplicate_address_objects(self, scope: Scope) -> List[Finding]:
        findings: List[Finding] = []
        by_value: Dict[str, List[AddressObject]] = defaultdict(list)

        for obj in scope.address_objects:
            if obj.value:
                by_value[obj.value].append(obj)

        for value, objects in by_value.items():
            if len(objects) > 1:
                object_names = [obj.name for obj in objects]
                for obj in objects:
                    findings.append(
                        Finding(
                            finding_code=FindingCode.DUP_OBJ,
                            severity=Severity.LOW,
                            scope_name=scope.name,
                            rule_name=obj.name,
                            issue="Duplicate address object value detected",
                            recommendation="Review duplicate address objects and consolidate where appropriate.",
                            estimated_minutes_to_resolve=5,
                            details={
                                "duplicate_value": value,
                                "duplicate_object_names": object_names,
                            },
                        )
                    )

        return findings

    def _check_shadow_rules(self, scope: Scope) -> List[Finding]:
        findings: List[Finding] = []
        rules = scope.security_rules

        for later_index, later_rule in enumerate(rules):
            if later_rule.disabled or later_rule.action.lower() != "allow":
                continue

            for earlier_index in range(later_index):
                earlier_rule = rules[earlier_index]

                if earlier_rule.disabled or earlier_rule.action.lower() != "allow":
                    continue

                if self._rule_shadows(earlier_rule, later_rule):
                    findings.append(
                        Finding(
                            finding_code=FindingCode.SHADOW_RULE,
                            severity=Severity.MEDIUM,
                            scope_name=scope.name,
                            rule_name=later_rule.name,
                            issue=f"Rule is shadowed by earlier rule '{earlier_rule.name}'",
                            recommendation=(
                                f"Review rule order. Consider moving '{later_rule.name}' above "
                                f"'{earlier_rule.name}' if needed, or remove it if redundant."
                            ),
                            estimated_minutes_to_resolve=15,
                            details={
                                "shadowing_rule": earlier_rule.name,
                                "shadowed_rule": later_rule.name,
                                "earlier_rule_position": earlier_index,
                                "later_rule_position": later_index,
                            },
                        )
                    )
                    break

        return findings

    def _rule_shadows(self, earlier_rule: SecurityRule, later_rule: SecurityRule) -> bool:
        return (
            self._covers(earlier_rule.from_zones, later_rule.from_zones)
            and self._covers(earlier_rule.to_zones, later_rule.to_zones)
            and self._covers(earlier_rule.source_addresses, later_rule.source_addresses)
            and self._covers(earlier_rule.destination_addresses, later_rule.destination_addresses)
            and self._covers(earlier_rule.services, later_rule.services)
            and self._covers(earlier_rule.applications, later_rule.applications)
        )

    def _covers(self, earlier_values: List[str], later_values: List[str]) -> bool:
        earlier = set(v.lower() for v in earlier_values if v)
        later = set(v.lower() for v in later_values if v)

        if "any" in earlier:
            return True

        if not later:
            return True

        return later.issubset(earlier)