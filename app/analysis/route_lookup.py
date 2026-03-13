from ipaddress import ip_address, ip_network
from typing import Any, Dict, List, Optional

from app.models.normalized_firewall_model import Interface, Scope


class RouteLookup:
    def __init__(self, scope: Scope):
        self.scope = scope

    def lookup(self, ip: str) -> Dict[str, Any]:
        """
        Resolve an IP against the scope's connected and static routing data.

        Resolution order:
        1. Connected subnet match from interface IP networks
        2. Longest-prefix static route match from normalized routes
        3. Default route fallback (0.0.0.0/0)

        Returns a normalized evidence structure for downstream zone resolution.
        """
        target_ip = self._safe_ip(ip)
        if target_ip is None:
            return {
                "status": "invalid_input",
                "ip": ip,
                "method": None,
                "matched_prefix": None,
                "egress_interface": None,
                "virtual_router": None,
                "route_type": None,
                "evidence": [f"Invalid IP address: {ip}"],
            }

        connected_match = self._lookup_connected(target_ip)
        if connected_match is not None:
            return connected_match

        static_match = self._lookup_static(target_ip)
        if static_match is not None:
            return static_match

        default_match = self._lookup_default_route()
        if default_match is not None:
            default_match["ip"] = str(target_ip)
            default_match["evidence"].insert(
                0,
                f"No connected subnet or specific static route matched {target_ip}",
            )
            return default_match

        return {
            "status": "unknown",
            "ip": str(target_ip),
            "method": None,
            "matched_prefix": None,
            "egress_interface": None,
            "virtual_router": None,
            "route_type": None,
            "evidence": [f"No connected subnet, static route, or default route matched {target_ip}"],
        }

    def _lookup_connected(self, target_ip) -> Optional[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []

        for iface in self.scope.interfaces:
            for network_str in iface.ip_networks:
                network = self._safe_network(network_str)
                if network is None:
                    continue

                if target_ip in network:
                    candidates.append(
                        {
                            "interface": iface.name,
                            "virtual_router": iface.virtual_router,
                            "matched_prefix": str(network),
                            "route_type": "connected",
                            "zone": iface.zone,
                        }
                    )

        if not candidates:
            return None

        best = self._select_best_prefix(candidates)
        return {
            "status": "resolved",
            "ip": str(target_ip),
            "method": "connected_subnet",
            "matched_prefix": best["matched_prefix"],
            "egress_interface": best["interface"],
            "virtual_router": best["virtual_router"],
            "route_type": "connected",
            "zone": best.get("zone"),
            "evidence": [
                f"IP {target_ip} matched connected subnet {best['matched_prefix']}",
                f"Connected subnet belongs to interface {best['interface']}",
            ],
        }

    def _lookup_static(self, target_ip) -> Optional[Dict[str, Any]]:
        candidates: List[Dict[str, Any]] = []

        for route in self.scope.routes:
            network = self._safe_network(route.destination)
            if network is None:
                continue

            if network.prefixlen == 0:
                continue

            if target_ip in network:
                candidates.append(
                    {
                        "interface": route.interface,
                        "virtual_router": route.virtual_router,
                        "matched_prefix": str(network),
                        "route_type": route.route_type,
                        "next_hop": route.next_hop,
                        "metric": route.metric,
                        "admin_distance": route.admin_distance,
                    }
                )

        if not candidates:
            return None

        best = self._select_best_prefix(candidates)
        evidence = [f"IP {target_ip} matched route {best['matched_prefix']}"]

        if best.get("interface"):
            evidence.append(f"Best route uses egress interface {best['interface']}")
        if best.get("next_hop"):
            evidence.append(f"Next hop is {best['next_hop']}")
        if best.get("virtual_router"):
            evidence.append(f"Route found in virtual router {best['virtual_router']}")

        return {
            "status": "resolved",
            "ip": str(target_ip),
            "method": "route_lookup",
            "matched_prefix": best["matched_prefix"],
            "egress_interface": best.get("interface"),
            "virtual_router": best.get("virtual_router"),
            "route_type": best.get("route_type", "static"),
            "zone": None,
            "evidence": evidence,
        }

    def _lookup_default_route(self) -> Optional[Dict[str, Any]]:
        defaults: List[Dict[str, Any]] = []

        for route in self.scope.routes:
            network = self._safe_network(route.destination)
            if network is None:
                continue

            if str(network) != "0.0.0.0/0":
                continue

            defaults.append(
                {
                    "interface": route.interface,
                    "virtual_router": route.virtual_router,
                    "matched_prefix": str(network),
                    "route_type": route.route_type,
                    "next_hop": route.next_hop,
                    "metric": route.metric,
                    "admin_distance": route.admin_distance,
                }
            )

        if not defaults:
            return None

        best = self._select_best_prefix(defaults)
        evidence = [f"Using default route {best['matched_prefix']}"]

        if best.get("interface"):
            evidence.append(f"Default route uses egress interface {best['interface']}")
        if best.get("next_hop"):
            evidence.append(f"Next hop is {best['next_hop']}")
        if best.get("virtual_router"):
            evidence.append(f"Default route found in virtual router {best['virtual_router']}")

        return {
            "status": "resolved",
            "ip": None,
            "method": "default_route",
            "matched_prefix": best["matched_prefix"],
            "egress_interface": best.get("interface"),
            "virtual_router": best.get("virtual_router"),
            "route_type": best.get("route_type", "static"),
            "zone": None,
            "evidence": evidence,
        }

    def _select_best_prefix(self, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Longest prefix wins.
        Tie-breaker: lower admin distance, then lower metric when available.
        """
        def sort_key(item: Dict[str, Any]):
            prefix_len = ip_network(item["matched_prefix"], strict=False).prefixlen
            admin_distance = item.get("admin_distance")
            metric = item.get("metric")

            admin_distance_sort = admin_distance if admin_distance is not None else 999999
            metric_sort = metric if metric is not None else 999999

            return (-prefix_len, admin_distance_sort, metric_sort)

        return sorted(candidates, key=sort_key)[0]

    @staticmethod
    def _safe_ip(value: str):
        try:
            return ip_address(value)
        except ValueError:
            return None

    @staticmethod
    def _safe_network(value: str):
        try:
            return ip_network(value, strict=False)
        except ValueError:
            return None

    @staticmethod
    def get_interface_by_name(scope: Scope, interface_name: Optional[str]) -> Optional[Interface]:
        if not interface_name:
            return None

        for iface in scope.interfaces:
            if iface.name == interface_name:
                return iface
        return None

    def debug_summary(self) -> Dict[str, Any]:
        return {
            "scope": self.scope.name,
            "interface_count": len(self.scope.interfaces),
            "route_count": len(self.scope.routes),
            "virtual_router_count": len(self.scope.virtual_routers),
        }