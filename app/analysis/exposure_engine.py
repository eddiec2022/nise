from collections import deque
from typing import Dict, List, Optional, Set

from app.models.normalized_firewall_model import FirewallConfig, Scope


class ExposureEngine:
    """
    Attack Path Engine (APE) v1.1

    Enhancements over v1:
    - validates the requested start zone
    - returns available zones when the zone is invalid
    - stores which allow rules create each zone-to-zone edge
    - returns exact path / rule chains for each reachable zone
    """

    def analyze_blast_radius(
        self,
        config: FirewallConfig,
        scope_name: str,
        start_zone: str,
    ) -> Dict:
        scope = self._find_scope(config, scope_name)

        if scope is None:
            return {"error": f"Scope '{scope_name}' not found."}

        graph = self._build_zone_graph(scope)
        available_zones = self._get_available_zones(scope, graph)

        if start_zone not in available_zones:
            return {
                "error": f"Start zone '{start_zone}' not found in scope '{scope_name}'.",
                "scope": scope_name,
                "start_zone": start_zone,
                "available_zones": available_zones,
            }

        attack_paths = self._find_attack_paths(graph, start_zone)
        reachable_zones = sorted(attack_paths.keys())

        return {
            "scope": scope_name,
            "start_zone": start_zone,
            "reachable_zones": reachable_zones,
            "available_zones": available_zones,
            "zone_graph": self._serialize_graph(graph),
            "attack_paths": attack_paths,
        }

    def _find_scope(self, config: FirewallConfig, scope_name: str) -> Optional[Scope]:
        for scope in config.scopes:
            if scope.name == scope_name:
                return scope
        return None

    def _build_zone_graph(self, scope: Scope) -> Dict[str, Dict[str, List[str]]]:
        graph: Dict[str, Dict[str, List[str]]] = {}

        for rule in scope.security_rules:
            if rule.disabled or rule.action != "allow":
                continue

            for src_zone in rule.from_zones:
                for dst_zone in rule.to_zones:
                    graph.setdefault(src_zone, {})
                    graph[src_zone].setdefault(dst_zone, [])

                    if rule.name not in graph[src_zone][dst_zone]:
                        graph[src_zone][dst_zone].append(rule.name)

        return graph

    def _get_available_zones(
        self,
        scope: Scope,
        graph: Dict[str, Dict[str, List[str]]],
    ) -> List[str]:
        zone_set: Set[str] = set(scope.zones)

        for src_zone, destinations in graph.items():
            zone_set.add(src_zone)
            zone_set.update(destinations.keys())

        for rule in scope.security_rules:
            zone_set.update(zone for zone in rule.from_zones if zone)
            zone_set.update(zone for zone in rule.to_zones if zone)

        return sorted(zone_set)

    def _find_attack_paths(
        self,
        graph: Dict[str, Dict[str, List[str]]],
        start_zone: str,
    ) -> Dict[str, List[Dict[str, str]]]:
        visited: Set[str] = {start_zone}
        queue = deque([start_zone])
        path_map: Dict[str, List[Dict[str, str]]] = {start_zone: []}

        while queue:
            current_zone = queue.popleft()

            for next_zone in sorted(graph.get(current_zone, {}).keys()):
                if next_zone in visited:
                    continue

                rule_names = graph[current_zone][next_zone]
                selected_rule = rule_names[0] if rule_names else "unknown-rule"

                path_map[next_zone] = path_map[current_zone] + [
                    {
                        "from_zone": current_zone,
                        "to_zone": next_zone,
                        "rule_name": selected_rule,
                    }
                ]

                visited.add(next_zone)
                queue.append(next_zone)

        path_map.pop(start_zone, None)
        return path_map

    def _serialize_graph(
        self,
        graph: Dict[str, Dict[str, List[str]]],
    ) -> Dict[str, Dict[str, List[str]]]:
        return {
            src_zone: {
                dst_zone: list(rule_names)
                for dst_zone, rule_names in sorted(destinations.items())
            }
            for src_zone, destinations in sorted(graph.items())
        }