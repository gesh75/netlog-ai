# Multi-layer topology renderer

netlog-ai builds a single graph of every device in a site and exposes it as
four protocol overlays — **PHYSICAL · BGP · OSPF · VXLAN**. Each overlay puts
the attributes that matter for that protocol in the right place: per-device
attributes (AS, RID, VTEP) ride on the *node*, per-link attributes (iface,
speed, area, VNIs) ride on the *edge*.

The renderer is Cytoscape.js + ELK layered, loaded via CDN — no build step.

## Visual contract per layer

- **PHYSICAL** — `hostname` on the node; abbreviated iface (`Et1`, `eth3`,
  `et1/3`) at each endpoint; **link speed** (`10G`, `100G`) on the midpoint,
  parallel to the line. IPs are hidden by default — toggle **Show IPs** to
  reveal `Et1 10.0.1.0` style. Solid blue line.

- **BGP** — `hostname · AS65001` on the node; edge label is just `EBGP` or
  `IBGP` (the AS is already on each node, so we don't repeat it). eBGP edges
  draw an arrowhead, iBGP edges are dashed.

- **OSPF** — `hostname · RID 10.255.0.3` on the node; edge label is `area 0`
  (or whichever area the adjacency rides). Green dashed.

- **VXLAN** — `hostname · VTEP 10.255.1.4` on the node; edge label lists
  shared VNIs (`VNI 10010,10020,10030`). Coral dashed. When a leaf has no
  local VNIs (e.g. EVPN-only signaling leaf), the VTEP still shows on the
  node — only the VNI list is omitted.

## Empty-state behavior

When a layer has zero edges anywhere on the site (e.g. **OSPF on a pure-BGP
Clos**), the canvas renders nodes only and shows a banner:

> ⚠ No OSPF (or any internal IGP) configured on this site — showing 9 devices only.

This avoids the "did the renderer break?" question — the user can tell at a
glance the protocol is absent.

## Layout

ELK runs once per site on first render and the resulting node positions are
auto-pinned to `localStorage` (key: `netlog-ai.topo.pins.<siteId>`). All
subsequent layer toggles reuse the same positions, so **BGP / OSPF / VXLAN
inherit the L1/L3 layout** instead of recomputing. Drag a node to override its
position; **Reset Layout** clears the pins and reruns ELK from scratch.

When a manifest declares POPs/regions per device, `Group by POP` wraps each
POP in a compound rectangle and uses `box` packing at the root with
`layered DOWN` inside each POP — so DCN-LAB shows DE-FRA · UK-LON · NL-AMS ·
EU-CDG · US-NYC as side-by-side clusters.

Tier hierarchy (top→bottom) is honored via ELK partitioning:
`superspine / core / fw` (0) → `spine / edge / rt` (1) → `leaf / dist / sw` (2).

## Speed resolution

For each interface, the parser tries these sources in order:

1. **Explicit config directive**
   - EOS / IOS: `speed 100g` or `speed 10000` (Mbps form) under interface block
   - Nokia SRL: `port-speed 100G` under `ethernet { }`
   - Junos: `set interfaces et-0/0/0 gigether-options speed 100g`
   All normalize to `100G` / `10G` / `1G` / `40G` / `25G` etc.

2. **Interface-name convention** (skipped for ambiguous names)
   - `HundredGigE*` → 100G
   - `FortyGigE*` → 40G
   - `TwentyFiveGig*` → 25G
   - `TenGig*` / `xe-*` → 10G
   - `GigabitEthernet*` / `ge-*` → 1G
   - `et-*` → 40G  ·  `mge-*` → 100G

3. **Site default** in `manifest.json`:

   ```json
   { "default_link_speed": "10G" }
   ```

   Useful for clab/docker labs where configs don't carry `speed` directives.
   All four bundled sites declare `10G`; override as needed.

The displayed link rate is `min(src_speed, dst_speed)` — both ends should
agree; mismatches are surfaced so they can be fixed.

## Multi-vendor parser coverage

The topology engine ingests configs from every shipped vendor:

| Vendor | Iface IPs | OSPF | BGP | VXLAN/VTEP | Speed |
|---|---|---|---|---|---|
| **Junos** (SRX/MX/EX/QFX) | `set interfaces ... family inet address` | `protocols ospf` blocks | `routing-options autonomous-system`, peer-as | `vtep-source-interface` | `gigether-options speed` |
| **Arista EOS** | `interface EthernetN { ip address ... }` | `router ospf` + `area` | `router bgp NN neighbor X.X.X.X remote-as` | `vxlan source-interface Loopback1` + `vxlan vni N` | `speed Xg` (or AF inference) |
| **Nokia SRL** | `interface ethernet-1/X { subinterface 0 { ipv4 { address X } } }` | (when present) | `network-instance default { protocols bgp ... }` | `system0` loopback as **implicit VTEP** when `afi-safi evpn` is signaled | `port-speed XG` |
| **FRR** | Quagga block syntax | `router ospf` + `interface ip ospf area X` | `router bgp NN neighbor remote-as M` | `interface lo` as **implicit VTEP** when `advertise-all-vni` is present; `vrf X { vni N }` for L3 VNIs | (no native speed directive) |

The shared `_shared_subnet()` matches `/28–/31` peer subnets to wire iface
endpoints onto edges. ASN-pair fallback handles Docker overlay BGP IPs that
don't match interface IPs (lab quirk).

## Tooltips & detail

Hover any node for: role · tier · POP · AS · Router-ID · VTEP · BGP AFs ·
L2/L3 VNIs · VRFs · protocols · finding severity.

Hover any edge for: source · target · iface names · IPs · subnet · description ·
BGP type · AFs · VRF · OSPF area · cost · timers · VTEPs · VNIs.

## File map

- `src/ai_log_analyzer/topology.py` — graph builder, edge model, manifest enrichment, layer assignment, speed aggregation
- `src/ai_log_analyzer/topology_infer.py` — config parser per vendor: interfaces, BGP peers/AS/AFs, OSPF iface attrs, VXLAN VTEP/VNI, speed
- `src/ai_log_analyzer/web/static/app.js` — `renderTopology` + `_renderCytoscape` + `_edgeLabels` + `_nodeLabel` + pin store
- `src/ai_log_analyzer/web/static/index.html` — layer chips, Group-by-POP toggle, Show IPs toggle, empty-state banner
- `sites/<siteId>/manifest.json` — per-site metadata (`role`, `pop`, `default_link_speed`, etc.)

## Adding a new vendor

1. Add iface/OSPF/BGP/VXLAN regexes (or a block parser) to `topology_infer.py`.
2. Make sure discovered IPs are appended to `uniq_ips` so `_shared_subnet()`
   can pick up adjacencies.
3. If the vendor uses an implicit VTEP source (loopback IP when EVPN is
   signaled), extend the heuristic at `# Implicit VTEP discovery` in
   `topology_infer.py`.
4. Add a sample device under `sites/<lab>/<host>.txt` and rebuild the manifest.
