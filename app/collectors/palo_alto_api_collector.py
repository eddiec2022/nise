from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from app.collectors.base import BaseCollector

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class PaloAltoAPICollector(BaseCollector):
    def __init__(
        self,
        host: str,
        api_key: str,
        port: int = 443,
        verify_ssl: bool = False,
        output_dir: str = "output/collected",
        timeout: int = 30,
    ) -> None:
        self.host = host
        self.api_key = api_key
        self.port = port
        self.verify_ssl = verify_ssl
        self.output_dir = Path(output_dir)
        self.timeout = timeout

    @property
    def base_url(self) -> str:
        return f"https://{self.host}:{self.port}/api/"

    def collect(self) -> Dict:
        self.output_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        prefix = f"{self.host}_{timestamp}"

        system_info_path = self.output_dir / f"{prefix}_system_info.xml"
        running_config_path = self.output_dir / f"{prefix}_running_config.xml"

        system_info_xml = self._get_system_info()
        running_config_xml = self._get_running_config()

        system_info_path.write_text(system_info_xml, encoding="utf-8")
        running_config_path.write_text(running_config_xml, encoding="utf-8")

        return {
            "collector": "palo_alto_api",
            "host": self.host,
            "status": "success",
            "system_info_file": str(system_info_path),
            "running_config_file": str(running_config_path),
            "message": "Collection completed successfully.",
        }

    def _get_system_info(self) -> str:
        params = {
            "type": "op",
            "cmd": "<show><system><info/></system></show>",
            "key": self.api_key,
        }
        response = requests.get(
            self.base_url,
            params=params,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.text

    def _get_running_config(self) -> str:
        params = {
            "type": "export",
            "category": "configuration",
            "key": self.api_key,
        }
        response = requests.get(
            self.base_url,
            params=params,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )
        response.raise_for_status()
        return response.text