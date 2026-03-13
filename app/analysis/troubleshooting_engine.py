from typing import Dict, List, Optional

from app.analysis.exposure_engine import ExposureEngine
from app.analysis.traffic_identity import TrafficIdentity, TrafficIdentityBuilder
from app.analysis.zone_resolver import ZoneResolver
from app.models.normalized_firewall_model import FirewallConfig, Scope, SecurityRule
from app.simulation.policy_simulator import PolicySimulator


class TroubleshootingEngine:
    """
    Connectivity Troubleshooting Engine v2.1

    Enhancements:
    - validates scope and zones
    - optionally auto-resolves source/destination zones from IPs
    - determines whether a zone-level allow path exists
    - supports application-only, protocol/port-only, or combined input
    - ranks the closest candidate rules
    - explains why traffic is allowed or blocked
    """

    MAX_CANDIDATES = 3

    def __init__(self) -> None:
        self.policy_simulator = PolicySimulator()
        self.exposure_engine = ExposureEngine()
        self.identity_builder = TrafficIdentityBuilder()

    def analyze_traffic(
        self,
        config: FirewallConfig,
        scope_name: str,
        source_zone: Optional[str],
        destination_zone: Optional[str],
        source_ip: str,
        destination_ip: str,
        application: Optional[str] = None,
        protocol: Optional[str] = None,
        port: Optional[int] = None,
    ) -> Dict:
        scope = self._find_scope(config, scope_name)
        if scope is None:
            return {
                "result": "error",
                "message": f"Scope '{scope_name}' not found.",
            }

        traffic = self.identity_builder.build(
            source_ip=source_ip,
            destination_ip=destination_ip,
            application=application,
            protocol=protocol,
            port=port,
        )

        if not traffic.has_application_context() and not traffic.has_service_context():
            return {
                "result": "error",
                "message": (
                    "At least one traffic identity must be provided: "
                    "application, or protocol/port."
                ),
            }

        available_zones = self._get_available_zones(config, scope_name)

        source_zone_resolution = None
        destination_zone_resolution = None

        if not source_zone:
            source_zone_resolution = self._resolve_zone(scope, source_ip)
            if source_zone_resolution["status"] != "resolved":
                return {
                    "result": "error",
                    "message": f"Unable to resolve source zone for IP '{source_ip}'.",
                    "scope": scope_name,
                    "source_ip": source_ip,
                    "resolution": source_zone_resolution,
                    "available_zones": available_zones,
                }
            source_zone = source_zone_resolution["zone"]

        if not destination_zone:
            destination_zone_resolution = self._resolve_zone(scope, destination_ip)
            if destination_zone_resolution["status"] != "resolved":
                return {
                    "result": "error",
                    "message": f"Unable to resolve destination zone for IP '{destination_ip}'.",
                    "scope": scope_name,
                    "destination_ip": destination_ip,
                    "resolution": destination_zone_resolution,
                    "available_zones": available_zones,
                }
            destination_zone = destination_zone_resolution["zone"]

        if source_zone not in available_zones:
            return {
                "result": "error",
                "message": f"Source zone '{source_zone}' not found in scope '{scope_name}'.",
                "available_zones": available_zones,
            }

        if destination_zone not in available_zones:
            return {
                "result": "error",
                "message": f"Destination zone '{destination_zone}' not found in scope '{scope_name}'.",
                "available_zones": available_zones,
            }

        blast_radius = self.exposure_engine.analyze_blast_radius(
            config=config,
            scope_name=scope_name,
            start_zone=source_zone,
        )

        zone_reachable = destination_zone in blast_radius.get("reachable_zones", [])
        zone_path = blast_radius.get("attack_paths", {}).get(destination_zone)

        object_map = self.policy_simulator._build_address_object_map(scope, config)
        group_map = self.policy_simulator._build_address_group_map(scope, config)

        candidate_rules: List[Dict] = []

        for index, rule in enumerate(scope.security_rules):
            if rule.disabled:
                continue

            evaluation = self._evaluate_rule(
                rule=rule,
                source_zone=source_zone,
                destination_zone=destination_zone,
                traffic=traffic,
                object_map=object_map,
                group_map=group_map,
            )

            if evaluation["matched"]:
                return {
                    "result": "matched",
                    "scope": scope_name,
                    "source_zone": source_zone,
                    "destination_zone": destination_zone,
                    "source_zone_resolution": source_zone_resolution,
                    "destination_zone_resolution": destination_zone_resolution,
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "application": traffic.application,
                    "protocol": traffic.protocol,
                    "port": traffic.port,
                    "candidate_applications": traffic.candidate_applications,
                    "candidate_services": sorted(traffic.candidate_services),
                    "inference_confidence": traffic.inference_confidence,
                    "rule_name": rule.name,
                    "rule_position": index,
                    "action": rule.action,
                    "zone_path_found": zone_reachable,
                    "zone_path": zone_path,
                    "explanation": (
                        f"Traffic matched rule '{rule.name}' at position {index}. "
                        f"Action: {rule.action}."
                    ),
                }

            candidate_rules.append(
                self._build_candidate_rule(
                    rule=rule,
                    rule_position=index,
                    evaluation=evaluation,
                )
            )

        top_candidates = self._select_top_candidates(candidate_rules)

        if not zone_reachable:
            return {
                "result": "blocked",
                "scope": scope_name,
                "source_zone": source_zone,
                "destination_zone": destination_zone,
                "source_zone_resolution": source_zone_resolution,
                "destination_zone_resolution": destination_zone_resolution,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "application": traffic.application,
                "protocol": traffic.protocol,
                "port": traffic.port,
                "candidate_applications": traffic.candidate_applications,
                "candidate_services": sorted(traffic.candidate_services),
                "inference_confidence": traffic.inference_confidence,
                "rule_name": None,
                "rule_position": None,
                "action": "deny",
                "zone_path_found": False,
                "zone_path": None,
                "explanation": (
                    f"No allow path was found from zone '{source_zone}' "
                    f"to zone '{destination_zone}'."
                ),
                "candidate_rules": top_candidates,
            }

        return {
            "result": "implicit_deny",
            "scope": scope_name,
            "source_zone": source_zone,
            "destination_zone": destination_zone,
            "source_zone_resolution": source_zone_resolution,
            "destination_zone_resolution": destination_zone_resolution,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "application": traffic.application,
            "protocol": traffic.protocol,
            "port": traffic.port,
            "candidate_applications": traffic.candidate_applications,
            "candidate_services": sorted(traffic.candidate_services),
            "inference_confidence": traffic.inference_confidence,
            "rule_name": None,
            "rule_position": None,
            "action": "deny",
            "zone_path_found": True,
            "zone_path": zone_path,
            "explanation": (
                "A zone-level allow path exists, but no rule fully matched the "
                "provided traffic identity."
            ),
            "candidate_rules": top_candidates,
        }

    def _resolve_zone(self, scope: Scope, ip: str) -> Dict:
        resolver = ZoneResolver(scope)
        return resolver.resolve(ip)

    def _find_scope(self, config: FirewallConfig, scope_name: str) -> Optional[Scope]:
        for scope in config.scopes:
            if scope.name == scope_name:
                return scope
        return None

    def _get_available_zones(self, config: FirewallConfig, scope_name: str) -> List[str]:
        scope = self._find_scope(config, scope_name)
        if scope is None:
            return []

        blast_radius = self.exposure_engine.analyze_blast_radius(
            config=config,
            scope_name=scope_name,
            start_zone=scope.zones[0] if scope.zones else "",
        )

        if "available_zones" in blast_radius:
            return blast_radius["available_zones"]

        zones = set(scope.zones)
        for rule in scope.security_rules:
            zones.update(z for z in rule.from_zones if z)
            zones.update(z for z in rule.to_zones if z)

        return sorted(zones)

    def _evaluate_rule(
        self,
        rule: SecurityRule,
        source_zone: str,
        destination_zone: str,
        traffic: TrafficIdentity,
        object_map: Dict,
        group_map: Dict,
    ) -> Dict:
        checks = {
            "source_zone": self._zone_matches(rule.from_zones, source_zone),
            "destination_zone": self._zone_matches(rule.to_zones, destination_zone),
            "source_address": self.policy_simulator._address_matches(
                rule.source_addresses,
                traffic.source_ip,
                object_map,
                group_map,
            ),
            "destination_address": self.policy_simulator._address_matches(
                rule.destination_addresses,
                traffic.destination_ip,
                object_map,
                group_map,
            ),
            "application": self._application_context_matches(rule, traffic),
            "service": self._service_context_matches(rule, traffic),
        }

        failed_checks = [
            self._check_label(check_name)
            for check_name, passed in checks.items()
            if not passed
        ]

        score = self._score_rule(checks)

        return {
            "matched": all(checks.values()),
            "checks": checks,
            "failed_checks": failed_checks,
            "score": score,
        }

    def _application_context_matches(
        self,
        rule: SecurityRule,
        traffic: TrafficIdentity,
    ) -> bool:
        if traffic.application:
            return self.policy_simulator._application_matches(
                rule.applications,
                traffic.application,
            )

        if not traffic.candidate_applications:
            return True

        for candidate_app in traffic.candidate_applications:
            if self.policy_simulator._application_matches(rule.applications, candidate_app):
                return True

        return False

    def _service_context_matches(
        self,
        rule: SecurityRule,
        traffic: TrafficIdentity,
    ) -> bool:
        if not traffic.candidate_services:
            return True

        applications_to_try = []
        if traffic.application:
            applications_to_try.append(traffic.application)
        applications_to_try.extend(
            app for app in traffic.candidate_applications if app not in applications_to_try
        )

        if not applications_to_try:
            applications_to_try = ["unknown"]

        for candidate_service in traffic.candidate_services:
            for candidate_app in applications_to_try:
                if self.policy_simulator._service_matches(
                    rule.services,
                    candidate_service,
                    candidate_app,
                ):
                    return True

        return False

    def _build_candidate_rule(
        self,
        rule: SecurityRule,
        rule_position: int,
        evaluation: Dict,
    ) -> Dict:
        concise_expectations = self._build_concise_expectations(
            rule=rule,
            checks=evaluation["checks"],
        )

        return {
            "rule_name": rule.name,
            "rule_position": rule_position,
            "failed_checks": evaluation["failed_checks"],
            "matched_checks": sum(1 for passed in evaluation["checks"].values() if passed),
            "score": evaluation["score"],
            "expectations": concise_expectations,
        }

    def _build_concise_expectations(
        self,
        rule: SecurityRule,
        checks: Dict[str, bool],
    ) -> List[str]:
        expectations: List[str] = []

        if not checks["source_zone"]:
            expectations.append(f"Expected source zone: {', '.join(rule.from_zones)}")

        if not checks["destination_zone"]:
            expectations.append(f"Expected destination zone: {', '.join(rule.to_zones)}")

        if not checks["source_address"]:
            expectations.append(
                f"Expected source address: {', '.join(rule.source_addresses)}"
            )

        if not checks["destination_address"]:
            expectations.append(
                f"Expected destination address: {', '.join(rule.destination_addresses)}"
            )

        if not checks["application"]:
            expectations.append(f"Expected application: {', '.join(rule.applications)}")

        if not checks["service"]:
            expectations.append(f"Expected service: {', '.join(rule.services)}")

        return expectations[:2]

    def _select_top_candidates(self, candidate_rules: List[Dict]) -> List[Dict]:
        ranked = sorted(
            candidate_rules,
            key=lambda candidate: (
                -candidate["score"],
                -candidate["matched_checks"],
                candidate["rule_position"],
                candidate["rule_name"].lower(),
            ),
        )
        return ranked[: self.MAX_CANDIDATES]

    def _score_rule(self, checks: Dict[str, bool]) -> int:
        weights = {
            "source_zone": 30,
            "destination_zone": 30,
            "application": 20,
            "service": 20,
            "source_address": 10,
            "destination_address": 10,
        }

        return sum(
            weight for check_name, weight in weights.items() if checks.get(check_name, False)
        )

    def _check_label(self, check_name: str) -> str:
        labels = {
            "source_zone": "source zone mismatch",
            "destination_zone": "destination zone mismatch",
            "source_address": "source address mismatch",
            "destination_address": "destination address mismatch",
            "application": "application mismatch",
            "service": "service mismatch",
        }
        return labels.get(check_name, check_name)

    @staticmethod
    def _zone_matches(rule_zones: List[str], zone: str) -> bool:
        if not rule_zones or "any" in rule_zones:
            return True
        return zone in rule_zones