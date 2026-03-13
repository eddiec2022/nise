from app.analysis.exposure_engine import ExposureEngine


def _normalize_criticality(value: str) -> str:
    if not value:
        return "medium"

    normalized = value.strip().lower()
    if normalized in {"critical", "high", "medium", "low"}:
        return normalized

    return "medium"


def _calculate_risk_label(exposed: bool, criticality: str, hop_count: int) -> str:
    if not exposed:
        return "NONE"

    if criticality == "critical":
        if hop_count <= 1:
            return "CRITICAL"
        if hop_count == 2:
            return "HIGH"
        return "MEDIUM"

    if criticality == "high":
        if hop_count <= 1:
            return "HIGH"
        if hop_count == 2:
            return "MEDIUM"
        return "LOW"

    if criticality == "medium":
        if hop_count <= 1:
            return "MEDIUM"
        if hop_count == 2:
            return "LOW"
        return "LOW"

    if hop_count <= 1:
        return "LOW"
    return "LOW"


def _risk_rank(risk_label: str) -> int:
    ranking = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "NONE": 1,
    }
    return ranking.get(risk_label, 0)


def analyze_critical_assets(config, scope_name, start_zone, critical_assets):
    """
    Determine whether defined critical assets are reachable
    from the specified start zone.

    critical_assets format:
    [
        {"name": "Domain Controller", "zone": "Server", "criticality": "high"},
        {"name": "Database", "zone": "DB", "criticality": "critical"},
    ]
    """

    engine = ExposureEngine()
    ape_result = engine.analyze_blast_radius(
        config=config,
        scope_name=scope_name,
        start_zone=start_zone,
    )

    if ape_result.get("error"):
        return ape_result

    reachable_zones = ape_result.get("reachable_zones", [])
    attack_paths = ape_result.get("attack_paths", {})

    results = []

    for asset in critical_assets:
        asset_name = asset["name"]
        asset_zone = asset["zone"]
        criticality = _normalize_criticality(asset.get("criticality", "medium"))

        exposed = asset_zone in reachable_zones
        path = attack_paths.get(asset_zone, [])
        hop_count = len(path)
        risk_label = _calculate_risk_label(exposed, criticality, hop_count)

        results.append(
            {
                "asset": asset_name,
                "zone": asset_zone,
                "criticality": criticality,
                "exposed": exposed,
                "hop_count": hop_count,
                "risk_label": risk_label,
                "path": path if path else None,
            }
        )

    results.sort(
        key=lambda asset: (
            -_risk_rank(asset["risk_label"]),
            asset["hop_count"],
            asset["asset"].lower(),
        )
    )

    return {
        "scope": scope_name,
        "start_zone": start_zone,
        "critical_assets": results,
    }