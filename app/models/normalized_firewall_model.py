from enum import Enum
from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class Vendor(str, Enum):
    PALO_ALTO = "palo_alto"
    UNKNOWN = "unknown"


class ScopeType(str, Enum):
    STANDALONE = "standalone"
    SHARED = "shared"
    DEVICE_GROUP = "device_group"
    TEMPLATE = "template"
    TEMPLATE_STACK = "template_stack"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCode(str, Enum):
    OPR = "OPR"
    MSEL = "MSEL"
    MSP = "MSP"
    MLF = "MLF"
    MDR = "MDR"
    DR = "DR"
    DUP_OBJ = "DUP_OBJ"
    SHADOW_RULE = "SHADOW_RULE"


class DeploymentMode(str, Enum):
    TAP = "tap"
    VIRTUAL_WIRE = "virtual_wire"
    LAYER2 = "layer2"
    LAYER3 = "layer3"
    UNKNOWN = "unknown"


class AddressObject(BaseModel):
    name: str
    value: Optional[str] = None
    description: Optional[str] = None
    raw: Dict = Field(default_factory=dict)


class AddressGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    raw: Dict = Field(default_factory=dict)


class Interface(BaseModel):
    name: str
    deployment_mode: DeploymentMode = DeploymentMode.UNKNOWN
    ip_networks: List[str] = Field(default_factory=list)
    parent_interface: Optional[str] = None
    tag: Optional[int] = None
    virtual_router: Optional[str] = None
    zone: Optional[str] = None
    vsys: Optional[str] = None
    comment: Optional[str] = None
    raw: Dict = Field(default_factory=dict)


class ZoneBinding(BaseModel):
    zone: str
    interfaces: List[str] = Field(default_factory=list)
    deployment_mode: DeploymentMode = DeploymentMode.UNKNOWN
    raw: Dict = Field(default_factory=dict)


class VirtualRouter(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)
    raw: Dict = Field(default_factory=dict)


class RouteEntry(BaseModel):
    destination: str
    interface: Optional[str] = None
    next_hop: Optional[str] = None
    route_type: str = "static"   # connected | static | ospf | bgp | rip | live
    metric: Optional[int] = None
    admin_distance: Optional[int] = None
    virtual_router: Optional[str] = None
    source: str = "config"       # config | live
    raw: Dict = Field(default_factory=dict)


class Scope(BaseModel):
    name: str
    scope_type: ScopeType = ScopeType.UNKNOWN

    zones: List[str] = Field(default_factory=list)
    deployment_modes: List[DeploymentMode] = Field(default_factory=list)

    address_objects: List[AddressObject] = Field(default_factory=list)
    address_groups: List[AddressGroup] = Field(default_factory=list)
    service_objects: List[str] = Field(default_factory=list)
    service_groups: List[str] = Field(default_factory=list)
    application_groups: List[str] = Field(default_factory=list)
    security_rules: List["SecurityRule"] = Field(default_factory=list)
    nat_rules: List[str] = Field(default_factory=list)

    interfaces: List[Interface] = Field(default_factory=list)
    zone_bindings: List[ZoneBinding] = Field(default_factory=list)
    virtual_routers: List[VirtualRouter] = Field(default_factory=list)
    routes: List[RouteEntry] = Field(default_factory=list)

    def summary(self) -> Dict[str, int]:
        return {
            "zones": len(self.zones),
            "deployment_modes": len(self.deployment_modes),
            "address_objects": len(self.address_objects),
            "address_groups": len(self.address_groups),
            "service_objects": len(self.service_objects),
            "service_groups": len(self.service_groups),
            "application_groups": len(self.application_groups),
            "security_rules": len(self.security_rules),
            "nat_rules": len(self.nat_rules),
            "interfaces": len(self.interfaces),
            "zone_bindings": len(self.zone_bindings),
            "virtual_routers": len(self.virtual_routers),
            "routes": len(self.routes),
        }


class SecurityRule(BaseModel):
    name: str
    from_zones: List[str] = Field(default_factory=list)
    to_zones: List[str] = Field(default_factory=list)
    source_addresses: List[str] = Field(default_factory=list)
    source_users: List[str] = Field(default_factory=list)
    destination_addresses: List[str] = Field(default_factory=list)
    applications: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    categories: List[str] = Field(default_factory=list)
    action: str = "allow"
    disabled: bool = False
    description: Optional[str] = None

    log_start: bool = False
    log_end: bool = False
    log_setting: Optional[str] = None

    profile_group: Optional[str] = None
    profile_antivirus: Optional[str] = None
    profile_antispyware: Optional[str] = None
    profile_vulnerability: Optional[str] = None
    profile_url_filtering: Optional[str] = None
    profile_file_blocking: Optional[str] = None
    profile_wildfire_analysis: Optional[str] = None

    raw: Dict = Field(default_factory=dict)


class Finding(BaseModel):
    finding_code: FindingCode
    severity: Severity
    scope_name: str
    rule_name: str
    issue: str
    recommendation: str
    estimated_minutes_to_resolve: int
    details: Dict = Field(default_factory=dict)


class FirewallConfig(BaseModel):
    vendor: Vendor = Vendor.UNKNOWN
    hostname: Optional[str] = None
    scopes: List[Scope] = Field(default_factory=list)
    source_file: Optional[str] = None
    config_type: Optional[str] = None

    def summary(self) -> Dict:
        return {
            "vendor": self.vendor.value,
            "hostname": self.hostname,
            "config_type": self.config_type,
            "scope_count": len(self.scopes),
            "scopes": {scope.name: scope.summary() for scope in self.scopes},
        }