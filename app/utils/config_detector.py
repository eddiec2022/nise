from pathlib import Path
from typing import Dict


class ConfigDetector:
    def detect(self, file_path: str) -> Dict[str, str]:
        path = Path(file_path)
        raw_text = path.read_text(encoding="utf-8", errors="ignore")
        lowered = raw_text.lower()

        # Palo Alto Panorama
        if "<device-group>" in lowered and "<template>" in lowered:
            return {
                "vendor": "palo_alto",
                "config_type": "panorama",
                "parser": "palo_alto",
            }

        # Palo Alto standalone XML
        if "<vsys>" in lowered and "<rulebase>" in lowered and "<devices>" in lowered:
            return {
                "vendor": "palo_alto",
                "config_type": "standalone",
                "parser": "palo_alto",
            }

        # Fortinet / FortiGate CLI config
        if "config firewall policy" in lowered or "config firewall address" in lowered:
            return {
                "vendor": "fortinet",
                "config_type": "fortigate_cli",
                "parser": "fortinet",
            }

        # Cisco ASA / FTD style clues
        if "access-list " in lowered or "object network" in lowered or "ngfw" in lowered:
            return {
                "vendor": "cisco",
                "config_type": "ftd_or_asa",
                "parser": "cisco",
            }

        # Juniper SRX
        if "security {" in lowered or "set security policies" in lowered:
            return {
                "vendor": "juniper",
                "config_type": "srx",
                "parser": "juniper",
            }

        return {
            "vendor": "unknown",
            "config_type": "unknown",
            "parser": "unknown",
        }