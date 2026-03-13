import csv
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

from app.models.normalized_firewall_model import Finding


class ReportExporter:
    def export_findings_csv(self, findings: List[Finding], output_path: str) -> None:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with output_file.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "FindingCode",
                    "Severity",
                    "ScopeName",
                    "RuleName",
                    "Issue",
                    "Recommendation",
                    "EstimatedMinutesToResolve",
                    "ObjectValue",
                    "DuplicateObjectNames",
                    "DuplicateCount",
                    "AnyCount",
                    "LogSetting",
                    "ProfileGroup",
                    "ShadowingRule",
                ]
            )

            for finding in findings:
                details = finding.details or {}

                duplicate_names = details.get("duplicate_object_names", [])
                if isinstance(duplicate_names, list):
                    duplicate_names_str = ";".join(duplicate_names)
                    duplicate_count = len(duplicate_names)
                else:
                    duplicate_names_str = str(duplicate_names)
                    duplicate_count = ""

                writer.writerow(
                    [
                        finding.finding_code.value,
                        finding.severity.value,
                        finding.scope_name,
                        finding.rule_name,
                        finding.issue,
                        finding.recommendation,
                        finding.estimated_minutes_to_resolve,
                        details.get("duplicate_value", ""),
                        duplicate_names_str,
                        duplicate_count,
                        details.get("any_count", ""),
                        details.get("log_setting", ""),
                        details.get("profile_group", ""),
                        details.get("shadowing_rule", ""),
                    ]
                )

    def group_findings(self, findings: List[Finding]) -> List[Dict]:
        grouped = defaultdict(list)

        for finding in findings:
            key = (finding.finding_code.value, finding.scope_name)
            grouped[key].append(finding)

        grouped_results = []

        for (code, scope), items in grouped.items():
            grouped_results.append(
                {
                    "finding_code": code,
                    "scope": scope,
                    "count": len(items),
                    "severity": items[0].severity.value,
                    "example_rule": items[0].rule_name,
                }
            )

        return grouped_results

    def top_impacted_scopes(self, findings: List[Finding], limit: int = 5) -> List:
        scope_counts = defaultdict(int)

        for finding in findings:
            scope_counts[finding.scope_name] += 1

        sorted_scopes = sorted(
            scope_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        return sorted_scopes[:limit]

    def quick_wins(self, findings: List[Finding]) -> Dict:
        quick_win_codes = {"DUP_OBJ", "DR", "MDR", "MSEL", "SHADOW_RULE"}

        wins = [f for f in findings if f.finding_code.value in quick_win_codes]

        return {
            "count": len(wins),
            "types": sorted(list(set(f.finding_code.value for f in wins))),
        }

    def build_executive_summary(self, findings: List[Finding]) -> Dict:
        severity_counts = Counter(f.severity.value for f in findings)
        finding_counts = Counter(f.finding_code.value for f in findings)
        total_minutes = sum(f.estimated_minutes_to_resolve for f in findings)

        top_scopes = self.top_impacted_scopes(findings)
        quick_win_data = self.quick_wins(findings)
        grouped_findings = self.group_findings(findings)

        return {
            "total_findings": len(findings),
            "severity_counts": dict(severity_counts),
            "finding_counts": dict(finding_counts),
            "estimated_total_minutes": total_minutes,
            "estimated_total_hours": round(total_minutes / 60, 2),
            "top_impacted_scopes": top_scopes,
            "quick_wins": quick_win_data,
            "grouped_findings": grouped_findings,
        }

    def export_executive_pdf(self, summary: Dict, output_path: str, customer_name: str = "Customer") -> None:
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        c = canvas.Canvas(str(output_file), pagesize=letter)
        _, height = letter

        y = height - 50
        c.setFont("Helvetica-Bold", 16)
        c.drawString(50, y, "NISE Executive Security Report")

        y -= 25
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Customer: {customer_name}")

        y -= 30
        c.setFont("Helvetica-Bold", 13)
        c.drawString(50, y, "Executive Summary")

        y -= 20
        c.setFont("Helvetica", 11)
        c.drawString(50, y, f"Total Findings: {summary['total_findings']}")

        y -= 18
        c.drawString(50, y, f"Estimated Remediation Effort: {summary['estimated_total_hours']} hours")

        y -= 30
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Severity Breakdown")

        y -= 20
        c.setFont("Helvetica", 11)
        for severity, count in summary["severity_counts"].items():
            c.drawString(70, y, f"{severity.title()}: {count}")
            y -= 16

        y -= 10
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Finding Breakdown")

        y -= 20
        c.setFont("Helvetica", 11)
        for finding_code, count in summary["finding_counts"].items():
            c.drawString(70, y, f"{finding_code}: {count}")
            y -= 16

        y -= 10
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Top Impacted Scopes")

        y -= 20
        c.setFont("Helvetica", 11)
        for scope_name, count in summary.get("top_impacted_scopes", []):
            c.drawString(70, y, f"{scope_name}: {count}")
            y -= 16

        y -= 10
        c.setFont("Helvetica-Bold", 12)
        c.drawString(50, y, "Quick Wins")

        y -= 20
        c.setFont("Helvetica", 11)
        quick_wins = summary.get("quick_wins", {})
        c.drawString(70, y, f"Quick Win Findings: {quick_wins.get('count', 0)}")
        y -= 16
        c.drawString(70, y, f"Types: {', '.join(quick_wins.get('types', []))}")

        c.save()