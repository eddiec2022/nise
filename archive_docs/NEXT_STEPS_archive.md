# NISE Development Roadmap

## Immediate Next Step

### APE v1.1 — Attack Path Engine Enhancements

Goals:

- validate start zone input
- display available zones when invalid
- track which firewall rule creates zone connectivity
- return rule-aware attack paths instead of reachable zones only

This upgrade transforms APE from a **zone reachability engine** into a **rule-aware attack path engine**.

---

## Next Major Feature

### Critical Asset Exposure Analysis

Goals:

- allow manual definition of critical assets
- detect whether those assets are reachable from exposed zones
- estimate breach exposure risk

Future enhancement:

- automatically detect likely critical assets based on traffic patterns and application signatures.

---

## Future Feature

### Connectivity Troubleshooting Engine

Goal:

Allow engineers to ask questions like:

```
Why can't server A reach server B?
```

```
NISE will analyze the following:

- firewall rule blocks
- missing policies
- routing issues
- policy misconfigurations
```

This feature will evolve into an AI-assisted troubleshooting assistant.

### Product Sequencing Decisions

```
The following development priorities have already been established:

- finish the core analysis engine first
- build the UI later
- prioritize exposure intelligence and troubleshooting
- postpone change automation until later versions
```

### Long Term Platform Expansion

```
NISE will eventually support analysis across:

- firewalls
- routers
- load balancers
- cloud security groups
- Azure Firewall policies
- AWS security groups
```

This enables full network security exposure modeling across hybrid environments.

### Future Intelligence Capabilities

```
Planned intelligence features include:

- ransomware attack simulation
- AI troubleshooting assistant
- threat intelligence integration
- cloud security visibility
- policy optimization recommendations
```