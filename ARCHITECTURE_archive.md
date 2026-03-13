# NISE Architecture

## Core Processing Pipeline

```
Configuration File / API Snapshot
↓
Parser Layer
↓
Normalized Firewall Model
↓
Analysis Engines
• Security Analyzer
• Policy Simulator
• Exposure Engine (APE)
↓
Reports / Intelligence
```

This pipeline allows NISE to convert vendor-specific firewall configurations into a **vendor-agnostic model**, enabling analysis, simulation, and exposure detection across multiple platforms.

---

# Parser Layer

Responsible for detecting vendor configuration formats and translating them into the normalized firewall model.

Directory:

```
app/parsers/
```

Key components:

- parser_dispatcher.py
- parser_registry.py
- palo_alto_parser.py
- base.py

Capabilities:

- vendor detection
- standalone vs Panorama detection
- object extraction
- policy extraction
- conversion to normalized model

Additional detection utility:

```
app/utils/config_detector.py
```

---

# Normalized Firewall Model

Location:

```
app/models/normalized_firewall_model.py
```

Core objects:

- FirewallConfig
- Scope
- SecurityRule
- AddressObject
- AddressGroup
- Finding

Purpose:

Provide a **vendor-agnostic representation of firewall configurations** so that all analysis engines operate on the same data structure regardless of vendor.

This model enables:

- cross-vendor policy analysis
- policy simulation
- exposure modeling
- attack path analysis

---

# Security Analyzer

Location:

```
app/analysis/security_analyzer.py
```

The analyzer identifies security weaknesses and configuration hygiene issues.

Current detections include:

- overly permissive rules
- missing session-end logging
- missing security profiles
- missing log forwarding
- duplicate address objects
- shadow rules
- missing descriptions
- disabled rules

Output:

- detailed CSV engineering report
- executive PDF report
- estimated remediation effort

---

# Policy Simulator

Location:

```
app/simulation/policy_simulator.py
```

Simulates firewall policy behavior to determine how traffic would be processed.

Capabilities:

- rule matching simulation
- address object resolution
- address group resolution
- subnet matching
- application and service matching
- implicit deny detection

Example question NISE answers:

```
Can host A reach host B on HTTPS?
```

---

# Exposure Engine (APE)

Location:

```
app/analysis/exposure_engine.py
```

APE = **Attack Path Engine**

Purpose:

Model network reachability and determine potential attack paths.

Current capabilities:

- build zone connectivity graph
- compute reachable zones
- perform blast radius analysis

Example use case:

```
If an attacker enters through the Public zone,
what internal zones are reachable?
```

Future capabilities:

- rule-aware path analysis
- critical asset exposure detection
- ransomware spread modeling

---

# Reporting Engine

Location:

```
app/reports/report_exporter.py
```

Produces two report types.

Engineering Reports:

- detailed CSV findings
- remediation estimates
- rule-level issues

Executive Reports:

- PDF summary
- severity breakdown
- finding counts
- quick wins
- impacted scopes

---

# Collector Framework

Location:

```
app/collectors/
```

Components:

- base.py
- registry.py
- palo_alto_api_collector.py

Purpose:

Allow NISE to collect configurations directly from live devices via API.

Current status:

Collector framework implemented.

Future collectors planned for:

- Palo Alto API
- SSH collectors
- cloud firewall collectors

---

# Application Entry Point

Main program entry:

```
main.py
```

Supported CLI modes:

- file
- collect
- simulate
- blast-radius

Examples:

```
python main.py file <config.xml>

python main.py collect <host> <api_key>

python main.py simulate <config> <scope> <source> <destination> <application> <service>

python main.py blast-radius <config> <scope> <zone>
```

---

# Current System Status

Working features:

- Palo Alto standalone parser
- Panorama parser
- normalized firewall model
- security analyzer
- duplicate object detection
- shadow rule detection
- CSV engineering reports
- executive PDF reports
- policy simulation engine
- blast radius analysis (APE v1)
- collector framework