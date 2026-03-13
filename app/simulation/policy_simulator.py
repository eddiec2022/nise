import ipaddress
import re
from typing import Dict, List, Optional, Set

from app.models.normalized_firewall_model import (
    AddressGroup,
    AddressObject,
    ApplicationGroup,
    FirewallConfig,
    Scope,
)


class PolicySimulator:
    APP_DEFAULT_PORTS = {
        "ssl": {"tcp/443"},
        "web-browsing": {"tcp/80"},
        "dns": {"udp/53", "tcp/53"},
        "ssh": {"tcp/22"},
        "ms-rdp": {"tcp/3389"},
        "smtp": {"tcp/25"},
        "pop3": {"tcp/110"},
        "imap": {"tcp/143"},
        "snmp": {"udp/161"},
        "ping": {"icmp"},
    }

    def simulate(
        self,
        config: FirewallConfig,
        scope_name: str,
        source: str,
        destination: str,
        application: str,
        service: str,
    ) -> Dict:
        scope = self._find_scope(config, scope_name)
        if scope is None:
            return {
                "result": "error",
                "message": f"Scope '{scope_name}' not found.",
            }

        object_map = self._build_address_object_map(scope, config)
        group_map = self._build_address_group_map(scope, config)
        app_group_map = self._build_application_group_map(scope, config)

        for index, rule in enumerate(scope.security_rules):
            if rule.disabled:
                continue

            if not self._address_matches(rule.source_addresses, source, object_map, group_map):
                continue
            if not self._address_matches(rule.destination_addresses, destination, object_map, group_map):
                continue
            if not self._application_matches(rule.applications, application, app_group_map):
                continue
            if not self._service_matches(rule.services, service, application):
                continue

            return {
                "result": "matched",
                "scope": scope.name,
                "rule_name": rule.name,
                "rule_position": index,
                "action": rule.action,
                "explanation": (
                    f"Traffic matched rule '{rule.name}' at position {index}. "
                    f"Action: {rule.action}."
                ),
            }

        return {
            "result": "implicit_deny",
            "scope": scope.name,
            "rule_name": None,
            "rule_position": None,
            "action": "deny",
            "explanation": "No matching allow rule found. Implicit deny would apply.",
        }

    def _find_scope(self, config: FirewallConfig, scope_name: str) -> Optional[Scope]:
        for scope in config.scopes:
            if scope.name == scope_name:
                return scope
        return None

    def _build_address_object_map(self, scope: Scope, config: FirewallConfig) -> Dict[str, AddressObject]:
        object_map: Dict[str, AddressObject] = {}

        for shared_scope in config.scopes:
            if shared_scope.name == "shared":
                for obj in shared_scope.address_objects:
                    object_map[obj.name.lower()] = obj

        for obj in scope.address_objects:
            object_map[obj.name.lower()] = obj

        return object_map

    def _build_address_group_map(self, scope: Scope, config: FirewallConfig) -> Dict[str, AddressGroup]:
        group_map: Dict[str, AddressGroup] = {}

        for shared_scope in config.scopes:
            if shared_scope.name == "shared":
                for grp in shared_scope.address_groups:
                    group_map[grp.name.lower()] = grp

        for grp in scope.address_groups:
            group_map[grp.name.lower()] = grp

        return group_map

    def _build_application_group_map(self, scope: Scope, config: FirewallConfig) -> Dict[str, ApplicationGroup]:
        app_group_map: Dict[str, ApplicationGroup] = {}

        for shared_scope in config.scopes:
            if shared_scope.name == "shared":
                for grp in shared_scope.application_groups:
                    app_group_map[grp.name.lower()] = grp

        for grp in scope.application_groups:
            app_group_map[grp.name.lower()] = grp

        return app_group_map

    def _address_matches(
        self,
        rule_values: List[str],
        candidate_ip: str,
        object_map: Dict[str, AddressObject],
        group_map: Dict[str, AddressGroup],
    ) -> bool:
        normalized = [v for v in rule_values if v]
        if not normalized:
            return False

        lowered = {v.lower() for v in normalized}
        if "any" in lowered:
            return True

        for value in normalized:
            if self._address_token_matches(value, candidate_ip, object_map, group_map, visited_groups=set()):
                return True

        return False

    def _address_token_matches(
        self,
        token: str,
        candidate_ip: str,
        object_map: Dict[str, AddressObject],
        group_map: Dict[str, AddressGroup],
        visited_groups: Set[str],
    ) -> bool:
        token_l = token.lower()

        if token_l == "any":
            return True

        if self._ip_or_subnet_matches(token, candidate_ip):
            return True

        if token_l in object_map:
            obj = object_map[token_l]
            if obj.value and self._ip_or_subnet_matches(obj.value, candidate_ip):
                return True

        if token_l in group_map:
            if token_l in visited_groups:
                return False
            visited_groups.add(token_l)

            for member in group_map[token_l].members:
                if self._address_token_matches(member, candidate_ip, object_map, group_map, visited_groups):
                    return True

        return False

    def _ip_or_subnet_matches(self, token: str, candidate_ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(candidate_ip)
        except ValueError:
            return False

        try:
            if "/" in token:
                net = ipaddress.ip_network(token, strict=False)
                return ip_obj in net
            token_ip = ipaddress.ip_address(token)
            return ip_obj == token_ip
        except ValueError:
            return False

    def _application_matches(
        self,
        rule_values: List[str],
        application: str,
        app_group_map: Optional[Dict[str, ApplicationGroup]] = None,
    ) -> bool:
        normalized = [v for v in rule_values if v]
        application = application.lower()

        if not normalized:
            return False

        lowered = {v.lower() for v in normalized}
        if "any" in lowered:
            return True

        for token in normalized:
            if self._application_token_matches(
                token=token,
                application=application,
                app_group_map=app_group_map or {},
                visited_groups=set(),
            ):
                return True

        return False

    def _application_token_matches(
        self,
        token: str,
        application: str,
        app_group_map: Dict[str, ApplicationGroup],
        visited_groups: Set[str],
    ) -> bool:
        token_l = token.lower()

        if token_l == "any":
            return True

        if token_l == application:
            return True

        if token_l in app_group_map:
            if token_l in visited_groups:
                return False

            visited_groups.add(token_l)

            for member in app_group_map[token_l].members:
                if self._application_token_matches(
                    token=member,
                    application=application,
                    app_group_map=app_group_map,
                    visited_groups=visited_groups,
                ):
                    return True

        return False

    def _service_matches(self, rule_values: List[str], service: str, application: str) -> bool:
        normalized = {v.lower() for v in rule_values if v}
        application = application.lower()
        normalized_service = self._normalize_service_input(service)

        if not normalized:
            return False

        if "any" in normalized:
            return True

        if normalized_service in normalized:
            return True

        if "application-default" in normalized:
            allowed_ports = self.APP_DEFAULT_PORTS.get(application, set())
            if normalized_service in allowed_ports:
                return True

        for rule_value in normalized:
            if self._service_token_matches(rule_value, normalized_service):
                return True

        return False

    def _normalize_service_input(self, service: str) -> str:
        """
        Normalize user input into protocol/port format used internally.

        Examples:
        - tcp-22 -> tcp/22
        - udp-53 -> udp/53
        - tcp/443 -> tcp/443
        - application-default -> application-default
        - icmp -> icmp
        """
        if not service:
            return ""

        service = service.strip().lower()

        if service in {"any", "application-default", "icmp"}:
            return service

        match = re.fullmatch(r"(tcp|udp)[/-](\d+)", service)
        if match:
            protocol, port = match.groups()
            return f"{protocol}/{port}"

        return service

    def _service_token_matches(self, rule_value: str, normalized_service: str) -> bool:
        """
        Match a rule service token against normalized traffic service.

        Supports:
        - tcp-22 / udp-53
        - tcp/22 / udp/53
        - named service objects only if their names exactly equal the test value
          (placeholder until service object parsing is added)
        """
        if rule_value == normalized_service:
            return True

        normalized_rule_value = self._normalize_service_input(rule_value)
        if normalized_rule_value == normalized_service:
            return True

        return False