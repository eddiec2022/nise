import json
import sys
from pathlib import Path

from app.analysis.critical_asset_engine import analyze_critical_assets
from app.analysis.exposure_engine import ExposureEngine
from app.analysis.security_analyzer import SecurityAnalyzer
from app.analysis.troubleshooting_engine import TroubleshootingEngine
from app.collectors.registry import CollectorRegistry
from app.parsers.parser_dispatcher import ParserDispatcher
from app.reports.report_exporter import ReportExporter
from app.simulation.policy_simulator import PolicySimulator


def analyze_config_file(file_path: str, customer_name: str = "Demo Customer") -> None:
    dispatcher = ParserDispatcher()

    try:
        detection, config = dispatcher.parse(file_path)
    except ValueError as exc:
        print("Detected config:")
        print({"vendor": "unknown", "config_type": "unknown", "parser": "unknown"})
        print(str(exc))
        return

    print("Detected config:")
    print(detection)

    analyzer = SecurityAnalyzer()
    findings = analyzer.analyze(config)

    print("NISE parser executed successfully.")
    print(config.summary())
    print(f"\nTotal findings: {len(findings)}")

    for finding in findings[:20]:
        print(
            f"[{finding.severity.value.upper()}] "
            f"{finding.finding_code.value} | "
            f"Scope={finding.scope_name} | "
            f"Rule={finding.rule_name} | "
            f"{finding.issue}"
        )

    reports_dir = Path("output")
    exporter = ReportExporter()

    csv_path = reports_dir / "findings.csv"
    pdf_path = reports_dir / "executive_report.pdf"

    exporter.export_findings_csv(findings, str(csv_path))
    summary = exporter.build_executive_summary(findings)
    exporter.export_executive_pdf(summary, str(pdf_path), customer_name=customer_name)

    print(f"\nCSV report written to: {csv_path}")
    print(f"PDF report written to: {pdf_path}")
    print(f"Executive summary: {summary}")


def run_file_analysis(file_path: str) -> None:
    analyze_config_file(file_path=file_path, customer_name="Demo Customer")


def run_collector(host: str, api_key: str) -> None:
    registry = CollectorRegistry()
    collector_class = registry.get_collector_class("palo_alto_api")

    if collector_class is None:
        print("No collector found.")
        return

    collector = collector_class(host=host, api_key=api_key)
    result = collector.collect()

    print("Collector result:")
    print(result)

    if result.get("status") != "success":
        print("Collection did not succeed, so analysis will not continue.")
        return

    running_config_file = result.get("running_config_file")
    if not running_config_file:
        print("No running config file returned from collector.")
        return

    print("\nStarting analysis of collected configuration...\n")
    analyze_config_file(file_path=running_config_file, customer_name=host)


def run_simulation(
    file_path: str,
    scope_name: str,
    source: str,
    destination: str,
    application: str,
    service: str,
) -> None:
    dispatcher = ParserDispatcher()
    _, config = dispatcher.parse(file_path)

    simulator = PolicySimulator()
    result = simulator.simulate(
        config=config,
        scope_name=scope_name,
        source=source,
        destination=destination,
        application=application,
        service=service,
    )

    print("Simulation result:")
    print(result)


def run_blast_radius(file_path: str, scope_name: str, start_zone: str) -> None:
    dispatcher = ParserDispatcher()
    _, config = dispatcher.parse(file_path)

    engine = ExposureEngine()
    result = engine.analyze_blast_radius(
        config=config,
        scope_name=scope_name,
        start_zone=start_zone,
    )

    print("Blast radius analysis:")

    if "error" in result:
        print(result["error"])

        available_zones = result.get("available_zones", [])
        if available_zones:
            print("\nAvailable zones:")
            for zone in available_zones:
                print(f"  - {zone}")
        return

    print(f"Start zone: {result.get('start_zone')}")

    reachable_zones = result.get("reachable_zones", [])
    print("\nReachable zones:")
    if reachable_zones:
        for zone in reachable_zones:
            print(f"  - {zone}")
    else:
        print("  None")

    attack_paths = result.get("attack_paths", {})
    print("\nAttack paths:")

    if attack_paths:
        for destination, hops in attack_paths.items():
            if not hops:
                continue

            print(f"\n  {destination}:")
            for hop in hops:
                print(
                    f"    {hop['from_zone']} -> {hop['to_zone']} "
                    f"(rule: {hop['rule_name']})"
                )
    else:
        print("  None")


def run_critical_assets(
    file_path: str,
    scope_name: str,
    start_zone: str,
    assets_file: str,
) -> None:
    dispatcher = ParserDispatcher()
    _, config = dispatcher.parse(file_path)

    with open(assets_file, "r", encoding="utf-8") as f:
        critical_assets = json.load(f)

    result = analyze_critical_assets(
        config=config,
        scope_name=scope_name,
        start_zone=start_zone,
        critical_assets=critical_assets,
    )

    if result.get("error"):
        print(result["error"])
        if result.get("available_zones"):
            print("Available zones:")
            for zone in result["available_zones"]:
                print(f"  - {zone}")
        return

    print("Critical Asset Exposure Analysis:")
    print(f"Scope: {result.get('scope')}")
    print(f"Start zone: {result.get('start_zone')}")

    for asset in result.get("critical_assets", []):
        print(f"\n{asset['asset']} ({asset['zone']})")
        print(f"Criticality: {asset['criticality'].upper()}")
        print("EXPOSED" if asset["exposed"] else "NOT REACHABLE")
        print(f"Risk: {asset['risk_label']}")
        print(f"Hops: {asset['hop_count']}")

        path = asset.get("path")
        if path:
            for hop in path:
                print(
                    f"  {hop['from_zone']} -> {hop['to_zone']} "
                    f"(rule: {hop['rule_name']})"
                )


def print_troubleshooting_result(result: dict, auto_mode: bool = False) -> None:
    print("Connectivity Troubleshooting Analysis:")

    if result.get("result") == "error":
        if result.get("scope"):
            print(f"Scope: {result.get('scope')}")

        if result.get("source_zone"):
            print(f"Source zone: {result.get('source_zone')}")
        if result.get("destination_zone"):
            print(f"Destination zone: {result.get('destination_zone')}")

        if result.get("source_ip"):
            print(f"Source IP: {result.get('source_ip')}")
        if result.get("destination_ip"):
            print(f"Destination IP: {result.get('destination_ip')}")

        print("Result: ERROR")
        print(f"Message: {result.get('message')}")

        resolution = result.get("resolution")
        if resolution:
            print("\nResolution details:")
            print(f"  Status: {resolution.get('status')}")

            if resolution.get("method"):
                print(f"  Method: {resolution.get('method')}")
            if resolution.get("matched_prefix"):
                print(f"  Matched prefix: {resolution.get('matched_prefix')}")
            if resolution.get("egress_interface"):
                print(f"  Egress interface: {resolution.get('egress_interface')}")
            if resolution.get("virtual_router"):
                print(f"  Virtual router: {resolution.get('virtual_router')}")

            evidence = resolution.get("evidence", [])
            if evidence:
                print("  Evidence:")
                for item in evidence:
                    print(f"    - {item}")

        available_zones = result.get("available_zones", [])
        if available_zones:
            print("\nAvailable zones:")
            for zone in available_zones:
                print(f"  - {zone}")
        return

    print(f"Scope: {result.get('scope')}")

    if auto_mode:
        print(f"Source IP: {result.get('source_ip')}")
        print(f"Destination IP: {result.get('destination_ip')}")

        print(f"Resolved source zone: {result.get('source_zone')}")
        source_zone_resolution = result.get("source_zone_resolution")
        if source_zone_resolution:
            if source_zone_resolution.get("matched_prefix"):
                print(f"  Route/Subnet: {source_zone_resolution.get('matched_prefix')}")
            elif source_zone_resolution.get("method"):
                print(f"  Method: {source_zone_resolution.get('method')}")

        print(f"Resolved destination zone: {result.get('destination_zone')}")
        destination_zone_resolution = result.get("destination_zone_resolution")
        if destination_zone_resolution:
            if destination_zone_resolution.get("matched_prefix"):
                print(f"  Route/Subnet: {destination_zone_resolution.get('matched_prefix')}")
            elif destination_zone_resolution.get("method"):
                print(f"  Method: {destination_zone_resolution.get('method')}")
    else:
        print(f"Source zone: {result.get('source_zone')}")
        print(f"Destination zone: {result.get('destination_zone')}")
        print(f"Source IP: {result.get('source_ip')}")
        print(f"Destination IP: {result.get('destination_ip')}")

    if result.get("application"):
        print(f"Application: {result.get('application')}")
    else:
        print("Application: not provided")

    if result.get("protocol") and result.get("port") is not None:
        print(f"Protocol/Port: {result.get('protocol')}/{result.get('port')}")
    else:
        print("Protocol/Port: not provided")

    candidate_applications = result.get("candidate_applications", [])
    if candidate_applications:
        print(f"Candidate applications: {', '.join(candidate_applications)}")

    candidate_services = result.get("candidate_services", [])
    if candidate_services:
        print(f"Candidate services: {', '.join(candidate_services)}")

    inference_confidence = result.get("inference_confidence")
    if inference_confidence and inference_confidence != "none":
        print(f"Inference confidence: {inference_confidence}")

    outcome = result.get("result")
    action = result.get("action")
    
    if outcome == "matched":
        if action == "allow":
            print("\nResult: ALLOWED")
        elif action == "deny":
            print("\nResult: DENIED")
        else:
            print("\nResult: MATCHED")
    elif outcome == "blocked":
        print("\nResult: BLOCKED")
    else:
        print("\nResult: IMPLICIT DENY")

    action = result.get("action")
    if action:
        print(f"Action: {action}")

    rule_name = result.get("rule_name")
    rule_position = result.get("rule_position")
    if rule_name is not None:
        print(f"Matched rule: {rule_name}")
        print(f"Rule position: {rule_position}")

    print(f"Explanation: {result.get('explanation')}")

    zone_path = result.get("zone_path")
    print("\nZone path:")
    if zone_path:
        for hop in zone_path:
            print(
                f"  {hop['from_zone']} -> {hop['to_zone']} "
                f"(rule: {hop['rule_name']})"
            )
    else:
        print("  None")

    candidate_rules = result.get("candidate_rules", [])
    if candidate_rules:
        best = candidate_rules[0]
        print(
            f"\nBest candidate rule: {best['rule_name']} "
            f"(position {best['rule_position']})"
        )

        print("\nClosest candidate rules:")
        for candidate in candidate_rules:
            print(
                f"  {candidate['rule_name']} "
                f"(position {candidate['rule_position']}): "
                f"{', '.join(candidate['failed_checks'])}"
            )

            for expectation in candidate.get("expectations", []):
                print(f"    {expectation}")


def run_troubleshoot(args: list[str]) -> None:
    """
    Supported forms:

    Application only:
      python main.py troubleshoot <config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <application>

    Protocol/port only:
      python main.py troubleshoot <config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <protocol> <port>

    Both:
      python main.py troubleshoot <config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <application> <protocol> <port>
    """
    if len(args) not in {7, 8, 9}:
        print("Usage:")
        print("  Application only:")
        print("    python main.py troubleshoot <path_to_config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <application>")
        print("  Protocol/port only:")
        print("    python main.py troubleshoot <path_to_config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <protocol> <port>")
        print("  Both:")
        print("    python main.py troubleshoot <path_to_config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <application> <protocol> <port>")
        return

    file_path = args[0]
    scope_name = args[1]
    source_zone = args[2]
    destination_zone = args[3]
    source_ip = args[4]
    destination_ip = args[5]

    application = None
    protocol = None
    port = None

    remaining = args[6:]

    if len(remaining) == 1:
        application = remaining[0]

    elif len(remaining) == 2:
        protocol = remaining[0]
        try:
            port = int(remaining[1])
        except ValueError:
            print(f"Invalid port: {remaining[1]}")
            return

    elif len(remaining) == 3:
        application = remaining[0]
        protocol = remaining[1]
        try:
            port = int(remaining[2])
        except ValueError:
            print(f"Invalid port: {remaining[2]}")
            return

    dispatcher = ParserDispatcher()
    _, config = dispatcher.parse(file_path)

    engine = TroubleshootingEngine()
    result = engine.analyze_traffic(
        config=config,
        scope_name=scope_name,
        source_zone=source_zone,
        destination_zone=destination_zone,
        source_ip=source_ip,
        destination_ip=destination_ip,
        application=application,
        protocol=protocol,
        port=port,
    )

    print_troubleshooting_result(result, auto_mode=False)


def run_troubleshoot_auto(args: list[str]) -> None:
    """
    Supported forms:

    Application only:
      python main.py troubleshoot-auto <config> <scope> <source_ip> <destination_ip> <application>

    Protocol/port only:
      python main.py troubleshoot-auto <config> <scope> <source_ip> <destination_ip> <protocol> <port>

    Both:
      python main.py troubleshoot-auto <config> <scope> <source_ip> <destination_ip> <application> <protocol> <port>
    """
    if len(args) not in {5, 6, 7}:
        print("Usage:")
        print("  Application only:")
        print("    python main.py troubleshoot-auto <path_to_config> <scope> <source_ip> <destination_ip> <application>")
        print("  Protocol/port only:")
        print("    python main.py troubleshoot-auto <path_to_config> <scope> <source_ip> <destination_ip> <protocol> <port>")
        print("  Both:")
        print("    python main.py troubleshoot-auto <path_to_config> <scope> <source_ip> <destination_ip> <application> <protocol> <port>")
        return

    file_path = args[0]
    scope_name = args[1]
    source_ip = args[2]
    destination_ip = args[3]

    application = None
    protocol = None
    port = None

    remaining = args[4:]

    if len(remaining) == 1:
        application = remaining[0]

    elif len(remaining) == 2:
        protocol = remaining[0]
        try:
            port = int(remaining[1])
        except ValueError:
            print(f"Invalid port: {remaining[1]}")
            return

    elif len(remaining) == 3:
        application = remaining[0]
        protocol = remaining[1]
        try:
            port = int(remaining[2])
        except ValueError:
            print(f"Invalid port: {remaining[2]}")
            return

    dispatcher = ParserDispatcher()
    _, config = dispatcher.parse(file_path)

    engine = TroubleshootingEngine()
    result = engine.analyze_traffic(
        config=config,
        scope_name=scope_name,
        source_zone=None,
        destination_zone=None,
        source_ip=source_ip,
        destination_ip=destination_ip,
        application=application,
        protocol=protocol,
        port=port,
    )

    print_troubleshooting_result(result, auto_mode=True)


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python main.py file <path_to_config>")
        print("  python main.py collect <host> <api_key>")
        print("  python main.py simulate <path_to_config> <scope> <source> <destination> <application> <service>")
        print("  python main.py blast-radius <path_to_config> <scope> <start_zone>")
        print("  python main.py critical-assets <path_to_config> <scope> <start_zone> <assets_json_file>")
        print("  python main.py troubleshoot <path_to_config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <application>")
        print("  python main.py troubleshoot <path_to_config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <protocol> <port>")
        print("  python main.py troubleshoot <path_to_config> <scope> <source_zone> <destination_zone> <source_ip> <destination_ip> <application> <protocol> <port>")
        print("  python main.py troubleshoot-auto <path_to_config> <scope> <source_ip> <destination_ip> <application>")
        print("  python main.py troubleshoot-auto <path_to_config> <scope> <source_ip> <destination_ip> <protocol> <port>")
        print("  python main.py troubleshoot-auto <path_to_config> <scope> <source_ip> <destination_ip> <application> <protocol> <port>")
        return

    mode = sys.argv[1]

    if mode == "file":
        run_file_analysis(sys.argv[2])

    elif mode == "collect":
        if len(sys.argv) < 4:
            print("Usage: python main.py collect <host> <api_key>")
            return
        run_collector(sys.argv[2], sys.argv[3])

    elif mode == "simulate":
        if len(sys.argv) < 8:
            print("Usage: python main.py simulate <path_to_config> <scope> <source> <destination> <application> <service>")
            return
        run_simulation(
            file_path=sys.argv[2],
            scope_name=sys.argv[3],
            source=sys.argv[4],
            destination=sys.argv[5],
            application=sys.argv[6],
            service=sys.argv[7],
        )

    elif mode == "blast-radius":
        if len(sys.argv) < 5:
            print("Usage: python main.py blast-radius <path_to_config> <scope> <start_zone>")
            return
        run_blast_radius(
            file_path=sys.argv[2],
            scope_name=sys.argv[3],
            start_zone=sys.argv[4],
        )

    elif mode == "critical-assets":
        if len(sys.argv) < 6:
            print("Usage: python main.py critical-assets <path_to_config> <scope> <start_zone> <assets_json_file>")
            return
        run_critical_assets(
            file_path=sys.argv[2],
            scope_name=sys.argv[3],
            start_zone=sys.argv[4],
            assets_file=sys.argv[5],
        )

    elif mode == "troubleshoot":
        run_troubleshoot(sys.argv[2:])

    elif mode == "troubleshoot-auto":
        run_troubleshoot_auto(sys.argv[2:])

    else:
        print(f"Unknown mode: {mode}")
        print("Use 'file', 'collect', 'simulate', 'blast-radius', 'critical-assets', 'troubleshoot', or 'troubleshoot-auto'.")


if __name__ == "__main__":
    main()