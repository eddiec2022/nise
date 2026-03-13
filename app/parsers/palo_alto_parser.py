from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from lxml import etree

from app.models.normalized_firewall_model import (
    AddressGroup,
    AddressObject,
    DeploymentMode,
    FirewallConfig,
    Interface,
    RouteEntry,
    Scope,
    ScopeType,
    SecurityRule,
    Vendor,
    VirtualRouter,
    ZoneBinding,
)
from app.parsers.base import BaseParser


class PaloAltoParser(BaseParser):
    def __init__(self, file_path: str):
        self.file_path = Path(file_path)
        self.tree = None
        self.root = None

    def load(self) -> None:
        raw_text = self.file_path.read_text(encoding="utf-8", errors="ignore")

        replacements = {
            "&QT;": '"',
            "&APOS;": "'",
        }

        for bad, good in replacements.items():
            raw_text = raw_text.replace(bad, good)

        parser = etree.XMLParser(recover=True, huge_tree=True)
        self.root = etree.fromstring(raw_text.encode("utf-8"), parser=parser)
        self.tree = etree.ElementTree(self.root)

    def parse(self) -> FirewallConfig:
        if self.root is None:
            self.load()

        if self._is_panorama():
            return self._parse_panorama()
        return self._parse_standalone()

    def _is_panorama(self) -> bool:
        return self.root.find(".//devices/entry/device-group") is not None

    def _parse_standalone(self) -> FirewallConfig:
        config = FirewallConfig(
            vendor=Vendor.PALO_ALTO,
            source_file=str(self.file_path),
            config_type="standalone",
        )

        hostname = self.root.findtext(".//devices/entry/deviceconfig/system/hostname")
        config.hostname = hostname

        device_entry = self.root.find(".//devices/entry")
        network_root = device_entry.find("./network") if device_entry is not None else None
        global_interfaces = self._parse_interfaces(network_root)
        global_virtual_routers, global_routes = self._parse_virtual_routers(network_root)

        vsys_entries = self.root.findall(".//devices/entry/vsys/entry")
        if not vsys_entries:
            vsys_entries = [None]

        for vsys in vsys_entries:
            vsys_name = vsys.get("name") if vsys is not None else "default"
            scope = Scope(name=vsys_name, scope_type=ScopeType.STANDALONE)

            zone_entries = vsys.findall("./zone/entry") if vsys is not None else []
            self._populate_zone_data(scope, zone_entries)

            addr_entries = vsys.findall("./address/entry") if vsys is not None else []
            scope.address_objects = [self._parse_address_object(entry) for entry in addr_entries]

            addr_group_entries = vsys.findall("./address-group/entry") if vsys is not None else []
            scope.address_groups = [self._parse_address_group(entry) for entry in addr_group_entries]

            svc_entries = vsys.findall("./service/entry") if vsys is not None else []
            scope.service_objects = self._extract_names(svc_entries)

            svc_group_entries = vsys.findall("./service-group/entry") if vsys is not None else []
            scope.service_groups = self._extract_names(svc_group_entries)

            app_group_entries = vsys.findall("./application-group/entry") if vsys is not None else []
            scope.application_groups = self._extract_names(app_group_entries)

            sec_rule_entries = vsys.findall("./rulebase/security/rules/entry") if vsys is not None else []
            scope.security_rules = [self._parse_security_rule(rule) for rule in sec_rule_entries]

            nat_rule_entries = vsys.findall("./rulebase/nat/rules/entry") if vsys is not None else []
            scope.nat_rules = self._extract_names(nat_rule_entries)

            zone_by_interface = self._build_zone_by_interface(scope.zone_bindings)
            vr_by_interface = self._build_vr_by_interface(global_virtual_routers)

            scope.interfaces = self._apply_interface_mappings(global_interfaces, zone_by_interface, vr_by_interface)
            scope.virtual_routers = [vr.model_copy(deep=True) for vr in global_virtual_routers]
            scope.routes = [route.model_copy(deep=True) for route in global_routes]

            self._refresh_scope_deployment_modes(scope)
            config.scopes.append(scope)

        return config

    def _parse_panorama(self) -> FirewallConfig:
        config = FirewallConfig(
            vendor=Vendor.PALO_ALTO,
            source_file=str(self.file_path),
            config_type="panorama",
        )

        hostname = self.root.findtext(".//devices/entry/deviceconfig/system/hostname")
        config.hostname = hostname

        shared_scope = Scope(name="shared", scope_type=ScopeType.SHARED)
        shared_scope.address_objects = [
            self._parse_address_object(entry)
            for entry in self.root.findall(".//shared/address/entry")
        ]
        shared_scope.address_groups = [
            self._parse_address_group(entry)
            for entry in self.root.findall(".//shared/address-group/entry")
        ]
        shared_scope.service_objects = self._extract_names(
            self.root.findall(".//shared/service/entry")
        )
        shared_scope.service_groups = self._extract_names(
            self.root.findall(".//shared/service-group/entry")
        )
        shared_scope.application_groups = self._extract_names(
            self.root.findall(".//shared/application-group/entry")
        )

        shared_pre_rules = self.root.findall(".//shared/pre-rulebase/security/rules/entry")
        shared_post_rules = self.root.findall(".//shared/post-rulebase/security/rules/entry")
        shared_scope.security_rules = [self._parse_security_rule(rule) for rule in (shared_pre_rules + shared_post_rules)]

        shared_scope.nat_rules = self._extract_names(
            self.root.findall(".//shared/pre-rulebase/nat/rules/entry")
        ) + self._extract_names(
            self.root.findall(".//shared/post-rulebase/nat/rules/entry")
        )

        if any(shared_scope.summary().values()):
            config.scopes.append(shared_scope)

        dg_entries = self.root.findall(".//devices/entry/device-group/entry")
        for dg in dg_entries:
            dg_name = dg.get("name")
            scope = Scope(name=dg_name, scope_type=ScopeType.DEVICE_GROUP)

            zone_entries = dg.findall("./vsys/entry/zone/entry")
            self._populate_zone_data(scope, zone_entries)

            scope.address_objects = [self._parse_address_object(entry) for entry in dg.findall("./address/entry")]
            scope.address_groups = [self._parse_address_group(entry) for entry in dg.findall("./address-group/entry")]
            scope.service_objects = self._extract_names(dg.findall("./service/entry"))
            scope.service_groups = self._extract_names(dg.findall("./service-group/entry"))
            scope.application_groups = self._extract_names(dg.findall("./application-group/entry"))

            dg_pre_rules = dg.findall("./pre-rulebase/security/rules/entry")
            dg_post_rules = dg.findall("./post-rulebase/security/rules/entry")
            scope.security_rules = [self._parse_security_rule(rule) for rule in (dg_pre_rules + dg_post_rules)]

            scope.nat_rules = (
                self._extract_names(dg.findall("./pre-rulebase/nat/rules/entry")) +
                self._extract_names(dg.findall("./post-rulebase/nat/rules/entry"))
            )

            self._refresh_scope_deployment_modes(scope)
            config.scopes.append(scope)

        template_entries = self.root.findall(".//devices/entry/template/entry")
        for template in template_entries:
            template_name = template.get("name")
            scope = Scope(name=template_name, scope_type=ScopeType.TEMPLATE)

            network_root = template.find("./config/devices/entry/network")
            zone_entries = template.findall("./config/devices/entry/vsys/entry/zone/entry")
            self._populate_zone_data(scope, zone_entries)

            scope.interfaces = self._parse_interfaces(network_root)
            scope.virtual_routers, scope.routes = self._parse_virtual_routers(network_root)

            zone_by_interface = self._build_zone_by_interface(scope.zone_bindings)
            vr_by_interface = self._build_vr_by_interface(scope.virtual_routers)
            scope.interfaces = self._apply_interface_mappings(scope.interfaces, zone_by_interface, vr_by_interface)

            self._refresh_scope_deployment_modes(scope)
            config.scopes.append(scope)

        return config

    def _populate_zone_data(self, scope: Scope, zone_entries: List[etree._Element]) -> None:
        scope.zones = self._extract_names(zone_entries)
        scope.zone_bindings = [self._parse_zone_binding(entry) for entry in zone_entries]
        self._refresh_scope_deployment_modes(scope)

    def _parse_zone_binding(self, zone_entry: etree._Element) -> ZoneBinding:
        network = zone_entry.find("./network")
        deployment_mode = DeploymentMode.UNKNOWN
        members: List[str] = []

        if network is not None:
            for xml_tag, mode in (
                ("layer3", DeploymentMode.LAYER3),
                ("layer2", DeploymentMode.LAYER2),
                ("virtual-wire", DeploymentMode.VIRTUAL_WIRE),
                ("tap", DeploymentMode.TAP),
            ):
                mode_node = network.find(f"./{xml_tag}")
                if mode_node is not None:
                    deployment_mode = mode
                    members = self._member_values(mode_node.findall("./member"))
                    break

        return ZoneBinding(
            zone=zone_entry.get("name", "unnamed-zone"),
            interfaces=members,
            deployment_mode=deployment_mode,
            raw={"xml_tag": zone_entry.tag},
        )

    def _parse_interfaces(self, network_root: Optional[etree._Element]) -> List[Interface]:
        if network_root is None:
            return []

        interface_root = network_root.find("./interface")
        if interface_root is None:
            return []

        interfaces: List[Interface] = []
        seen: Set[Tuple[str, DeploymentMode]] = set()

        interfaces.extend(self._parse_family_mode_entries(interface_root.find("./ethernet"), seen))
        interfaces.extend(self._parse_family_mode_entries(interface_root.find("./aggregate-ethernet"), seen))
        interfaces.extend(self._parse_simple_units(interface_root.find("./loopback"), DeploymentMode.LAYER3, seen))
        interfaces.extend(self._parse_simple_units(interface_root.find("./tunnel"), DeploymentMode.LAYER3, seen))
        interfaces.extend(self._parse_simple_units(interface_root.find("./vlan"), DeploymentMode.LAYER3, seen))

        return interfaces

    def _parse_family_mode_entries(
        self,
        family_root: Optional[etree._Element],
        seen: Set[Tuple[str, DeploymentMode]],
    ) -> List[Interface]:
        if family_root is None:
            return []

        parsed: List[Interface] = []
        for entry in family_root.findall("./entry"):
            base_name = entry.get("name")
            if not base_name:
                continue

            for xml_tag, mode in (
                ("layer3", DeploymentMode.LAYER3),
                ("layer2", DeploymentMode.LAYER2),
                ("virtual-wire", DeploymentMode.VIRTUAL_WIRE),
                ("tap", DeploymentMode.TAP),
            ):
                mode_node = entry.find(f"./{xml_tag}")
                if mode_node is None:
                    continue

                parsed.extend(
                    self._parse_interface_entry(
                        entry=entry,
                        mode_node=mode_node,
                        mode=mode,
                        base_name=base_name,
                        seen=seen,
                    )
                )

        return parsed

    def _parse_simple_units(
        self,
        family_root: Optional[etree._Element],
        mode: DeploymentMode,
        seen: Set[Tuple[str, DeploymentMode]],
    ) -> List[Interface]:
        if family_root is None:
            return []

        parsed: List[Interface] = []
        for unit in family_root.findall("./units/entry"):
            iface = self._build_interface(
                name=unit.get("name"),
                deployment_mode=mode,
                node=unit,
                parent_interface=None,
            )
            if iface is not None and (iface.name, iface.deployment_mode) not in seen:
                seen.add((iface.name, iface.deployment_mode))
                parsed.append(iface)
        return parsed

    def _parse_interface_entry(
        self,
        entry: etree._Element,
        mode_node: etree._Element,
        mode: DeploymentMode,
        base_name: str,
        seen: Set[Tuple[str, DeploymentMode]],
    ) -> List[Interface]:
        parsed: List[Interface] = []

        base_iface = self._build_interface(
            name=base_name,
            deployment_mode=mode,
            node=entry,
            parent_interface=None,
        )
        if base_iface is not None and (base_iface.name, base_iface.deployment_mode) not in seen:
            seen.add((base_iface.name, base_iface.deployment_mode))
            parsed.append(base_iface)

        for unit in mode_node.findall("./units/entry"):
            unit_iface = self._build_interface(
                name=unit.get("name"),
                deployment_mode=mode,
                node=unit,
                parent_interface=base_name,
            )
            if unit_iface is not None and (unit_iface.name, unit_iface.deployment_mode) not in seen:
                seen.add((unit_iface.name, unit_iface.deployment_mode))
                parsed.append(unit_iface)

        return parsed

    def _build_interface(
        self,
        name: Optional[str],
        deployment_mode: DeploymentMode,
        node: etree._Element,
        parent_interface: Optional[str],
    ) -> Optional[Interface]:
        if not name:
            return None

        ip_networks = [entry.get("name") for entry in node.findall("./ip/entry") if entry.get("name")]
        tag_text = node.findtext("./tag")
        tag = int(tag_text) if tag_text and tag_text.isdigit() else None

        return Interface(
            name=name,
            deployment_mode=deployment_mode,
            ip_networks=ip_networks,
            parent_interface=parent_interface,
            tag=tag,
            comment=node.findtext("./comment"),
            raw={"xml_tag": node.tag},
        )

    def _parse_virtual_routers(
        self,
        network_root: Optional[etree._Element],
    ) -> tuple[List[VirtualRouter], List[RouteEntry]]:
        if network_root is None:
            return [], []

        virtual_routers: List[VirtualRouter] = []
        routes: List[RouteEntry] = []

        for vr_entry in network_root.findall("./virtual-router/entry"):
            vr_name = vr_entry.get("name", "unnamed-virtual-router")
            vr_interfaces = self._member_values(vr_entry.findall("./interface/member"))

            virtual_routers.append(
                VirtualRouter(
                    name=vr_name,
                    interfaces=vr_interfaces,
                    raw={"xml_tag": vr_entry.tag},
                )
            )

            for route_entry in vr_entry.findall("./routing-table/ip/static-route/entry"):
                metric_text = route_entry.findtext("./metric")
                admin_distance_text = route_entry.findtext("./admin-dist")

                routes.append(
                    RouteEntry(
                        destination=route_entry.findtext("./destination", default="0.0.0.0/0"),
                        interface=route_entry.findtext("./interface"),
                        next_hop=(
                            route_entry.findtext("./nexthop/ip-address")
                            or route_entry.findtext("./nexthop/next-vr")
                            or route_entry.findtext("./nexthop/discard")
                        ),
                        route_type="static",
                        metric=self._safe_int(metric_text),
                        admin_distance=self._safe_int(admin_distance_text),
                        virtual_router=vr_name,
                        source="config",
                        raw={"name": route_entry.get("name"), "xml_tag": route_entry.tag},
                    )
                )

        return virtual_routers, routes

    def _apply_interface_mappings(
        self,
        interfaces: List[Interface],
        zone_by_interface: Dict[str, str],
        vr_by_interface: Dict[str, str],
    ) -> List[Interface]:
        enriched: List[Interface] = []
        for iface in interfaces:
            clone = iface.model_copy(deep=True)
            clone.zone = zone_by_interface.get(clone.name)
            clone.virtual_router = vr_by_interface.get(clone.name)
            enriched.append(clone)
        return enriched

    def _build_zone_by_interface(self, bindings: List[ZoneBinding]) -> Dict[str, str]:
        zone_by_interface: Dict[str, str] = {}
        for binding in bindings:
            for iface in binding.interfaces:
                zone_by_interface[iface] = binding.zone
        return zone_by_interface

    def _build_vr_by_interface(self, virtual_routers: List[VirtualRouter]) -> Dict[str, str]:
        vr_by_interface: Dict[str, str] = {}
        for vr in virtual_routers:
            for iface in vr.interfaces:
                vr_by_interface[iface] = vr.name
        return vr_by_interface

    def _refresh_scope_deployment_modes(self, scope: Scope) -> None:
        modes = {binding.deployment_mode for binding in scope.zone_bindings if binding.deployment_mode != DeploymentMode.UNKNOWN}
        modes.update(iface.deployment_mode for iface in scope.interfaces if iface.deployment_mode != DeploymentMode.UNKNOWN)
        scope.deployment_modes = sorted(modes, key=lambda mode: mode.value)

    def _parse_address_object(self, entry: etree._Element) -> AddressObject:
        value = (
            entry.findtext("./ip-netmask")
            or entry.findtext("./ip-range")
            or entry.findtext("./fqdn")
            or entry.findtext("./ip-wildcard")
        )

        return AddressObject(
            name=entry.get("name", "unnamed-address-object"),
            value=value,
            description=entry.findtext("./description"),
            raw={"xml_tag": entry.tag},
        )

    def _parse_address_group(self, entry: etree._Element) -> AddressGroup:
        members = [m.text for m in entry.findall("./static/member") if m.text]
        return AddressGroup(
            name=entry.get("name", "unnamed-address-group"),
            members=members,
            description=entry.findtext("./description"),
            raw={"xml_tag": entry.tag},
        )

    def _parse_security_rule(self, rule_entry: etree._Element) -> SecurityRule:
        profile_group = rule_entry.findtext("./profile-setting/group/member")

        return SecurityRule(
            name=rule_entry.get("name", "unnamed-rule"),
            from_zones=self._member_values(rule_entry.findall("./from/member")),
            to_zones=self._member_values(rule_entry.findall("./to/member")),
            source_addresses=self._member_values(rule_entry.findall("./source/member")),
            source_users=self._member_values(rule_entry.findall("./source-user/member")),
            destination_addresses=self._member_values(rule_entry.findall("./destination/member")),
            applications=self._member_values(rule_entry.findall("./application/member")),
            services=self._member_values(rule_entry.findall("./service/member")),
            categories=self._member_values(rule_entry.findall("./category/member")),
            action=rule_entry.findtext("./action", default="allow"),
            disabled=self._to_bool(rule_entry.findtext("./disabled", default="no")),
            description=rule_entry.findtext("./description"),
            log_start=self._to_bool(rule_entry.findtext("./log-start", default="no")),
            log_end=self._to_bool(rule_entry.findtext("./log-end", default="no")),
            log_setting=rule_entry.findtext("./log-setting"),
            profile_group=profile_group,
            profile_antivirus=rule_entry.findtext("./profile-setting/profiles/virus/member"),
            profile_antispyware=rule_entry.findtext("./profile-setting/profiles/spyware/member"),
            profile_vulnerability=rule_entry.findtext("./profile-setting/profiles/vulnerability/member"),
            profile_url_filtering=rule_entry.findtext("./profile-setting/profiles/url-filtering/member"),
            profile_file_blocking=rule_entry.findtext("./profile-setting/profiles/file-blocking/member"),
            profile_wildfire_analysis=rule_entry.findtext("./profile-setting/profiles/wildfire-analysis/member"),
            raw={"xml_tag": rule_entry.tag},
        )

    @staticmethod
    def _extract_names(entries: List[etree._Element]) -> List[str]:
        return [entry.get("name") for entry in entries if entry.get("name")]

    @staticmethod
    def _member_values(entries: List[etree._Element]) -> List[str]:
        return [entry.text for entry in entries if entry.text]

    @staticmethod
    def _safe_int(value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _to_bool(value: str) -> bool:
        return str(value).strip().lower() in {"yes", "true", "1"}