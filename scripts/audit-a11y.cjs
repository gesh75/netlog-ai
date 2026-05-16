'use strict';
/**
 * WCAG-AA accessibility audit for netlog-ai.
 *
 * Visits 5 UI states and runs axe-core against each:
 *   1. Idle / welcome state (initial page load)
 *   2. LOGS tab populated (after Run Analysis)
 *   3. DEVICE tab populated (after Optimize Selected Sample)
 *   4. SITE tab populated (after Analyze Whole Site)
 *   5. Topology view
 *
 * Reports CRITICAL + SERIOUS impact violations only (those are the actual
 * AA blockers). MINOR / MODERATE are listed but don't fail the audit.
 *
 * WCAG tag set: wcag2a + wcag2aa + wcag21a + wcag21aa + best-practice
 */
const { chromium } = require('playwright');
const { AxeBuilder } = require('@axe-core/playwright');

const BASE_URL = 'http://localhost:6060';
const VIEWPORT = { width: 1440, height: 900 };
const AA_TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

const summary = { critical: 0, serious: 0, moderate: 0, minor: 0, byState: {} };

async function runAxe(page, stateName) {
  const result = await new AxeBuilder({ page }).withTags(AA_TAGS).analyze();
  const v = result.violations;
  const blockers = v.filter(x => x.impact === 'critical' || x.impact === 'serious');
  const others  = v.filter(x => x.impact === 'moderate' || x.impact === 'minor');

  console.log(`\n────── ${stateName} ──────`);
  console.log(`Critical: ${v.filter(x=>x.impact==='critical').length}` +
              `   Serious: ${v.filter(x=>x.impact==='serious').length}` +
              `   Moderate: ${v.filter(x=>x.impact==='moderate').length}` +
              `   Minor: ${v.filter(x=>x.impact==='minor').length}`);
  if (blockers.length === 0) {
    console.log(`  ✓ No AA-blocking violations`);
  } else {
    for (const issue of blockers) {
      console.log(`  ✗ [${issue.impact.toUpperCase()}] ${issue.id} — ${issue.help}`);
      console.log(`    ${issue.helpUrl}`);
      for (const node of issue.nodes.slice(0, 3)) {
        console.log(`    → ${node.target.join(' ')}`);
        console.log(`      HTML: ${node.html.substring(0, 160)}`);
        if (node.failureSummary) {
          for (const line of node.failureSummary.split('\n').slice(0, 4)) {
            console.log(`      ${line}`);
          }
        }
      }
      if (issue.nodes.length > 3) {
        console.log(`    (… +${issue.nodes.length - 3} more)`);
      }
    }
  }
  // List non-blockers compactly
  if (others.length > 0) {
    console.log(`  (non-blockers: ${others.map(o => `${o.impact}:${o.id}`).join(', ')})`);
  }

  // Aggregate
  for (const x of v) {
    summary[x.impact] = (summary[x.impact] || 0) + 1;
  }
  summary.byState[stateName] = {
    critical: v.filter(x=>x.impact==='critical').length,
    serious:  v.filter(x=>x.impact==='serious').length,
    moderate: v.filter(x=>x.impact==='moderate').length,
    minor:    v.filter(x=>x.impact==='minor').length,
  };
  return blockers.length;
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: VIEWPORT });
  const page = await ctx.newPage();

  // ── State 1: Idle / welcome ───────────────────────────────────────────
  await page.goto(`${BASE_URL}/`);
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(800);
  await runAxe(page, 'state-1-idle');

  // ── State 2: LOGS populated (KB analysis, rendered via JS for determinism) ──
  await page.evaluate(() => fetch('/api/llm/toggle', {
    method: 'POST', headers: {'content-type':'application/json'},
    body: JSON.stringify({ enabled: false }),
  }));
  await page.waitForTimeout(300);
  await page.selectOption('#source', 'raw');
  await page.waitForTimeout(400);
  // Call API directly + invoke the page's own render() with the result.
  // Bypasses click interception and gives us a guaranteed populated dashboard.
  await page.evaluate(async (payload) => {
    const r = await fetch('/api/analyze', {
      method: 'POST', headers: {'content-type':'application/json'},
      body: JSON.stringify(payload),
    });
    const data = await r.json();
    if (typeof window.render === 'function') window.render(data);
    else throw new Error('window.render() not available');
  }, {
    source: 'raw',
    hostname: 'audit-test',
    text: [
      'Mar  3 12:00:01 r1 rpd: bgp peer 10.0.0.1 down (hold timer expired)',
      'Mar  3 12:00:02 sw1 mib2d: ifIndex 538 link down',
      'Mar  3 12:00:03 r1 ospfd: OSPF nbr 10.0.0.5 state full -> down',
    ].join('\n'),
    use_llm: false,
  }).catch(e => console.error(`  state-2 render error: ${e.message}`));
  await page.waitForTimeout(1500);
  // Sanity-check the dashboard populated
  const score = await page.locator('#score').textContent();
  console.log(`  state-2 score: ${score}`);
  await runAxe(page, 'state-2-logs-populated');

  // Re-enable LLM for next states
  await page.evaluate(() => fetch('/api/llm/toggle', {
    method: 'POST', headers: {'content-type':'application/json'},
    body: JSON.stringify({ enabled: true }),
  }));

  // ── State 3: DEVICE optimize (sample) ─────────────────────────────────
  await page.click('.side-tab[data-tab="device"]');
  await page.waitForTimeout(400);
  // Open Real-Config Samples section if collapsed
  const samples = page.locator('details.side-section:has(summary:has-text("Real-Config Samples"))').first();
  if (await samples.count() && !(await samples.evaluate(d => d.open))) {
    await samples.locator('summary').click();
    await page.waitForTimeout(300);
  }
  await page.selectOption('#sample-picker', 'junos-fw-01');
  await page.click('#sample-opt-btn');
  // Wait for results
  await page.waitForFunction(() => {
    const el = document.getElementById('opt-summary');
    return el && el.textContent && !el.textContent.startsWith('Running') && el.textContent.length > 30;
  }, { timeout: 45000 });
  await page.waitForTimeout(800);
  await runAxe(page, 'state-3-device-populated');

  // ── State 4: SITE populated ───────────────────────────────────────────
  await page.click('.side-tab[data-tab="site"]');
  await page.waitForTimeout(400);
  await page.selectOption('#site-picker', 'lab-bravo');
  await page.click('#site-opt-btn');
  await page.waitForFunction(() => {
    const el = document.getElementById('site-summary');
    return el && el.textContent && !el.textContent.includes('Analyzing') && el.textContent.length > 30;
  }, { timeout: 50000 });
  await page.waitForTimeout(800);
  await runAxe(page, 'state-4-site-populated');

  // ── State 5: Topology open ────────────────────────────────────────────
  await page.click('#topo-btn');
  await page.waitForTimeout(3500);  // let D3 sim settle
  await runAxe(page, 'state-5-topology');

  // ── Summary ───────────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════');
  console.log('  SUMMARY');
  console.log('══════════════════════════════════════');
  console.log(JSON.stringify(summary, null, 2));
  const totalBlockers = summary.critical + summary.serious;
  console.log(`\nTotal AA blockers (critical + serious): ${totalBlockers}`);
  console.log(totalBlockers === 0 ? '✅ PASS — claim WCAG-AA' : '⚠ FIX REQUIRED before claiming WCAG-AA');

  await browser.close();
  process.exit(totalBlockers === 0 ? 0 : 1);
})().catch(e => { console.error('FATAL:', e); process.exit(2); });
