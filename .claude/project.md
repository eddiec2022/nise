# NISE — Project Intelligence File

## 1. Project Overview

NISE (Network Intelligence & Security Engine) is a deterministic firewall analysis engine.

It parses vendor-specific firewall configurations, normalizes them into a vendor-neutral internal model, and runs a suite of simulation engines for:

- **Policy evaluation** — determine whether traffic is permitted or denied by security rules
- **Attack path analysis** — enumerate reachable paths through the network from a given source
- **Connectivity troubleshooting** — explain why a specific flow is allowed or blocked, including zone resolution, route lookup, and rule matching

---

## 2. Architectural Principles

- Vendor configurations are parsed into normalized models before any analysis occurs
- Simulation engines operate exclusively on normalized models — never on raw vendor data
- Vendor-specific behavior (syntax, semantics, quirks) must be encapsulated in the parser or vendor adapter layers
- Analysis engines must remain fully vendor-neutral
- All results must be deterministic and explainable — probabilistic or heuristic reasoning is not permitted

---

## 3. Current System Components

| Component | Description |
|---|---|
| Palo Alto configuration parser | Parses PAN-OS XML configs into normalized model objects |
| Normalized firewall model | Vendor-neutral representation of zones, interfaces, routes, rules, address objects, and services |
| Policy simulation engine | Evaluates security policy rules against a normalized traffic flow |
| Route-aware zone resolution | Resolves source/destination zones by performing route and default-route lookups |
| Attack path engine | Enumerates permitted paths across zones and rule sets from a given source |
| Connectivity troubleshooting engine | Explains allow/deny decisions step by step, including zone, route, and rule matching |
| Dockerized runtime environment | Containerized execution environment for consistent deployments |
| Unit test framework | Test coverage for parsers, models, and simulation engines |

---

## 4. Coding Standards

- **Language:** Python 3.x
- Maintain clear separation between:
  - **Parser layer** — vendor-specific config ingestion
  - **Model layer** — normalized, vendor-neutral data structures
  - **Simulation engines** — policy and route evaluation logic
  - **Analysis modules** — troubleshooting, attack path, and reporting
- All logic must be deterministic — the same input must always produce the same output
- Vendor-specific logic must never leak into analysis or simulation layers
- Rule ordering must be preserved wherever it affects evaluation outcomes

---

## 5. Development Workflow

- **Architecture decisions** are made externally by the system architect
- **Claude Code** generates implementation code based on those architectural instructions
- **The human developer** reviews and integrates the generated code

Claude Code does not propose architectural changes unless explicitly asked. Implementation follows the design as specified.

---

## 6. Upcoming Milestone — NAT-Aware Firewall Simulation

The next milestone extends NISE with full NAT simulation capability.

**Requirements:**

- **Normalized NAT rule model** — represent source NAT, destination NAT, and static NAT rules in a vendor-neutral structure
- **NAT simulation engine** — evaluate NAT rules against a traffic flow and produce translated addresses/ports
- **Pre-NAT and post-NAT flow identity** — both identities must be preserved and traceable throughout the simulation
- **Evaluation order** — NAT evaluation must occur before security policy evaluation, consistent with how real firewalls process traffic
- **Troubleshooting integration** — the troubleshooting engine must explain NAT decisions as part of its step-by-step output

---

## 7. Safety Rules

- Claude Code must **never restructure the architecture** without an explicit instruction to do so
- All changes must be **incremental** and **compatible** with the current architecture
- When in doubt, implement the narrowest change that satisfies the requirement
