# Reproducible audits

## `audit-a11y.cjs` — WCAG-AA verification

Runs `@axe-core/playwright` against 5 representative UI states:

1. Idle / welcome
2. LOGS tab populated
3. DEVICE tab populated (Optimize a sample)
4. SITE tab populated (Analyze Whole Site)
5. Topology rendered

Rule set: WCAG 2.0 A + AA, WCAG 2.1 A + AA. Reports critical + serious
violations as AA blockers; moderate/minor are listed but don't fail the run.

### Requirements

```bash
npm init -y
npm install playwright @axe-core/playwright
npx playwright install chromium
```

### Run

```bash
# 1. Make sure netlog-ai is serving on localhost:6060
ai-log-analyzer serve

# 2. Run the audit in a separate shell
node scripts/audit-a11y.cjs
```

### Expected output

```
state-1-idle:               critical=0  serious=0  moderate=0  minor=0
state-2-logs-populated:     critical=0  serious=0  moderate=0  minor=0
state-3-device-populated:   critical=0  serious=0  moderate=0  minor=0
state-4-site-populated:     critical=0  serious=0  moderate=0  minor=0
state-5-topology:           critical=0  serious=0  moderate=0  minor=0

Total AA blockers: 0
✅ PASS
```
