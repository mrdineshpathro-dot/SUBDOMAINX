"""Standalone HTML report.

The generated file is completely self-contained: CSS and JavaScript are
embedded, no fonts, images or network resources are referenced, so the report
works offline (useful for handing results to a customer or attaching them to a
report).
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

from .. import __version__
from ..models import Host, ScanResult
from ..utils.helpers import truncate
from ..utils.logging import get_logger

_STYLES = """
:root{
  --bg:#0e1117; --panel:#161b22; --panel2:#1c2230; --line:#2b3242;
  --fg:#e6edf3; --muted:#8b949e; --accent:#58a6ff; --green:#3fb950;
  --yellow:#d29922; --red:#f85149; --purple:#bc8cff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:14px;line-height:1.5}
.wrap{max-width:1400px;margin:0 auto;padding:24px}
header{border:1px solid var(--line);border-radius:12px;padding:20px 24px;
  background:linear-gradient(135deg,#111827,#0e1117);margin-bottom:18px}
h1{margin:0 0 4px;font-size:24px;letter-spacing:.5px}
h2{font-size:16px;margin:28px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--line)}
h3{font-size:14px;margin:16px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.sub{color:var(--muted);margin:0}
.meta{margin-top:12px;color:var(--muted);font-size:12px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-top:16px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.card .v{font-size:22px;font-weight:600;margin-top:4px}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{cursor:pointer;color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;
  letter-spacing:.06em;position:sticky;top:0;background:var(--panel);z-index:1}
th:hover{color:var(--accent)}
tbody tr:hover{background:var(--panel2)}
td.host{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--accent)}
td.wrap-any{word-break:break-all}
.tag{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;
  border:1px solid var(--line);background:var(--panel2);color:var(--muted);margin:1px 2px 1px 0}
.score{font-weight:700;font-family:ui-monospace,monospace}
.s-very-high{color:var(--green)}.s-high{color:var(--green)}
.s-medium{color:var(--yellow)}.s-low{color:#db6d28}.s-very-low{color:var(--red)}
.ok{color:var(--green)}.warn{color:var(--yellow)}.bad{color:var(--red)}.muted{color:var(--muted)}
.controls{display:flex;gap:10px;align-items:center;margin:10px 0}
input[type=search]{flex:1;background:var(--panel);border:1px solid var(--line);
  border-radius:8px;padding:8px 12px;color:var(--fg);font-size:13px}
input[type=search]:focus{outline:none;border-color:var(--accent)}
select{background:var(--panel);border:1px solid var(--line);border-radius:8px;
  padding:8px 10px;color:var(--fg);font-size:13px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:12px;
  padding:16px 18px;margin-bottom:16px;overflow-x:auto}
.bar{height:8px;border-radius:4px;background:var(--panel2);overflow:hidden;min-width:60px}
.bar > span{display:block;height:100%;background:var(--accent)}
ul{margin:6px 0;padding-left:18px}
svg{width:100%;height:auto;max-height:460px}
.graph-legend{display:flex;gap:16px;color:var(--muted);font-size:12px;margin-top:6px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:5px}
footer{color:var(--muted);font-size:12px;margin:30px 0 10px;text-align:center}
.note{background:var(--panel2);border-left:3px solid var(--accent);padding:10px 14px;
  border-radius:6px;color:var(--muted);margin:12px 0}
"""

_SCRIPT = """
function sortTable(table, col, asc){
  const body = table.tBodies[0];
  const rows = Array.from(body.querySelectorAll('tr'));
  rows.sort((a,b)=>{
    const x = a.children[col].dataset.sort !== undefined ? a.children[col].dataset.sort : a.children[col].textContent.trim();
    const y = b.children[col].dataset.sort !== undefined ? b.children[col].dataset.sort : b.children[col].textContent.trim();
    const nx = parseFloat(x), ny = parseFloat(y);
    if(!isNaN(nx) && !isNaN(ny)){ return asc ? nx-ny : ny-nx; }
    return asc ? String(x).localeCompare(String(y)) : String(y).localeCompare(String(x));
  });
  rows.forEach(r => body.appendChild(r));
}
document.querySelectorAll('table.sortable').forEach(table=>{
  table.querySelectorAll('thead th').forEach((th, idx)=>{
    let asc = true;
    th.addEventListener('click', ()=>{
      sortTable(table, idx, asc); asc = !asc;
      table.querySelectorAll('thead th').forEach(o=>o.classList.remove('sorted'));
      th.classList.add('sorted');
    });
  });
});
const search = document.getElementById('host-search');
if(search){
  search.addEventListener('input', ()=>{
    const q = search.value.toLowerCase();
    document.querySelectorAll('#hosts tbody tr').forEach(row=>{
      row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
    });
  });
}
const filter = document.getElementById('category-filter');
if(filter){
  filter.addEventListener('change', ()=>{
    const v = filter.value;
    document.querySelectorAll('#hosts tbody tr').forEach(row=>{
      row.style.display = (v === 'all' || row.dataset.category === v) ? '' : 'none';
    });
  });
}
"""


def _esc(value: Any) -> str:
    """HTML-escape any value (all report data is untrusted input)."""
    return html.escape(str(value if value is not None else ""), quote=True)


def render_html(result: ScanResult) -> str:
    """Render a complete, standalone HTML report."""
    hosts = result.hosts_by_confidence()
    stats = result.statistics
    categories = sorted({h.category.value for h in hosts})
    wildcard = (result.graph or {}).get("wildcard") or {}

    parts: List[str] = [
        "<!DOCTYPE html>",
        '<html lang="en"><head><meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>SUBDOMAINX report - {_esc(result.target)}</title>",
        f"<style>{_STYLES}</style>",
        "</head><body><div class='wrap'>",
        "<header>",
        "<h1>SUBDOMAINX</h1>",
        "<p class='sub'>Passive Subdomain Discovery &amp; Asset Intelligence</p>",
        f"<div class='meta'>Target <strong>{_esc(result.target)}</strong> &middot; "
        f"generated {_esc(stats.finished_at or '')} &middot; "
        f"duration {stats.duration_seconds:.2f}s &middot; v{_esc(__version__)} &middot; "
        f"API keys: <span class='ok'>none</span></div>",
        "<div class='cards'>",
        _card("Unique hosts", len(hosts)),
        _card("Live hosts", stats.http_live),
        _card("DNS resolved", stats.dns_resolved),
        _card("Historical", stats.historical),
        _card("Interesting", stats.interesting),
        _card("Sources used", stats.sources_successful),
        _card("Cloud assets", stats.cloud_assets),
        _card("CDN hosts", stats.cdn_hosts),
        "</div>",
        "</header>",
    ]

    if wildcard:
        state = str(wildcard.get("state") or "UNKNOWN")
        css = "ok" if "NO WILDCARD" in state else ("warn" if "PARTIAL" in state else "bad")
        parts.append(
            f"<div class='note'>Wildcard DNS: <span class='{css}'><strong>{_esc(state)}</strong></span> "
            f"({wildcard.get('resolved_count', 0)} of {max(1, len(wildcard.get('probes') or []))} random probes resolved). "
            "Hosts whose answers match the wildcard signature are penalised in the confidence score.</div>"
        )

    # -- discovery table ---------------------------------------------------
    parts.append("<h2>Discovery</h2>")
    parts.append("<div class='controls'>")
    parts.append(
        "<input type='search' id='host-search' placeholder='Filter hosts, sources, titles, technology...'>"
    )
    options = "".join(f"<option value='{_esc(c)}'>{_esc(c)}</option>" for c in categories)
    parts.append(
        f"<select id='category-filter'><option value='all'>All categories</option>{options}</select>"
    )
    parts.append("</div>")
    parts.append("<div class='panel'><table class='sortable' id='hosts'>")
    parts.append(
        "<thead><tr>"
        "<th>Host</th><th>Confidence</th><th>Sources</th><th>DNS</th><th>HTTP</th>"
        "<th>Status</th><th>Title</th><th>Technology</th><th>CDN</th><th>Category</th>"
        "<th>First seen</th><th>Last seen</th>"
        "</tr></thead><tbody>"
    )
    for host in hosts:
        parts.append(_host_row(host))
    parts.append("</tbody></table></div>")

    # -- source performance ------------------------------------------------
    parts.append("<h2>Source performance</h2>")
    parts.append("<div class='panel'><table class='sortable'>")
    parts.append(
        "<thead><tr><th>Source</th><th>Status</th><th>Results</th><th>Success</th>"
        "<th>Errors</th><th>Rate limits</th><th>Parser failures</th>"
        "<th>Avg latency</th><th>Last error</th></tr></thead><tbody>"
    )
    for name, health in sorted((result.source_health or {}).items()):
        css = "ok" if health.status.ok else ("warn" if health.status.value == "RATE_LIMITED" else "bad")
        parts.append(
            "<tr>"
            f"<td class='host'>{_esc(name)}</td>"
            f"<td class='{css}'>{_esc(health.status.value)}</td>"
            f"<td data-sort='{health.results}'>{health.results}</td>"
            f"<td data-sort='{health.success_count}'>{health.success_count}</td>"
            f"<td data-sort='{health.error_count}'>{health.error_count}</td>"
            f"<td data-sort='{health.rate_limit_events}'>{health.rate_limit_events}</td>"
            f"<td data-sort='{health.parser_failures}'>{health.parser_failures}</td>"
            f"<td data-sort='{health.average_response_time_ms}'>{health.average_response_time_ms:.0f} ms</td>"
            f"<td class='muted wrap-any'>{_esc(truncate(health.last_error or '', 90))}</td>"
            "</tr>"
        )
    if not result.source_health:
        parts.append("<tr><td colspan='9' class='muted'>No sources executed.</td></tr>")
    parts.append("</tbody></table></div>")

    # -- interesting hosts -------------------------------------------------
    interesting = [h for h in hosts if h.interesting]
    if interesting:
        parts.append("<h2>Interesting hosts</h2>")
        parts.append("<div class='panel'><table class='sortable'>")
        parts.append(
            "<thead><tr><th>Host</th><th>Priority</th><th>Confidence</th><th>HTTP</th>"
            "<th>Reason</th></tr></thead><tbody>"
        )
        for host in sorted(interesting, key=lambda h: (-h.priority, h.host))[:200]:
            parts.append(
                "<tr>"
                f"<td class='host'>{_esc(host.host)}</td>"
                f"<td data-sort='{host.priority}'>{host.priority}</td>"
                f"<td data-sort='{host.confidence}'>{host.confidence}</td>"
                f"<td>{host.http.status_code if host.http and host.http.status_code else '-'}</td>"
                f"<td class='wrap-any'>{_esc('; '.join(host.interesting_reasons[:3]))}</td>"
                "</tr>"
            )
        parts.append("</tbody></table></div>")
        parts.append(
            "<div class='note'>\"Interesting\" describes reconnaissance priority only. "
            "It is <strong>not</strong> a vulnerability statement.</div>"
        )

    # -- changes -----------------------------------------------------------
    changes = result.changes or {}
    if changes:
        parts.append("<h2>Changes</h2>")
        parts.append("<div class='panel'>")
        for title, key, css in (("New hosts", "new", "ok"), ("Removed hosts", "removed", "bad")):
            values = changes.get(key) or []
            parts.append(f"<h3>{title} ({len(values)})</h3>")
            if values:
                parts.append("<ul>")
                for value in values[:300]:
                    parts.append(f"<li class='host {css}'>{_esc(value)}</li>")
                parts.append("</ul>")
            else:
                parts.append("<p class='muted'>none</p>")
        changed = changes.get("changed") or []
        parts.append(f"<h3>Changed hosts ({len(changed)})</h3>")
        if changed:
            parts.append("<table class='sortable'><thead><tr><th>Host</th><th>Change</th></tr></thead><tbody>")
            for record in changed[:200]:
                notes = "<br>".join(_esc(n) for n in record.get("changes", [])[:6])
                parts.append(f"<tr><td class='host'>{_esc(record.get('host'))}</td><td>{notes}</td></tr>")
            parts.append("</tbody></table>")
        else:
            parts.append("<p class='muted'>none</p>")
        if changes.get("unchanged") is not None:
            parts.append(f"<p class='muted'>Unchanged hosts: {int(changes['unchanged'])}</p>")
        parts.append("</div>")

    # -- technology / cdn / cloud summary ----------------------------------
    parts.append("<h2>Asset intelligence</h2>")
    parts.append("<div class='panel'>")
    parts.append(_tag_summary("Technologies", _count([t.name for h in hosts for t in h.technologies])))
    parts.append(_tag_summary("CDN providers", _count([h.cdn.provider for h in hosts if h.cdn and h.cdn.provider])))
    parts.append(_tag_summary("Cloud providers", _count([h.cloud.provider for h in hosts if h.cloud])))
    parts.append(_tag_summary("Categories", _count([h.category.value for h in hosts])))
    parts.append("</div>")

    # -- source correlation graph ------------------------------------------
    graph = result.graph or {}
    if graph.get("nodes"):
        parts.append("<h2>Source correlation</h2>")
        parts.append("<div class='panel'>")
        parts.append(_render_graph(graph))
        parts.append(
            "<div class='graph-legend'>"
            "<span><span class='dot' style='background:#bc8cff'></span>passive source</span>"
            "<span><span class='dot' style='background:#58a6ff'></span>discovered host</span>"
            "<span class='muted'>More independent sources per host = stronger evidence.</span>"
            "</div>"
        )
        parts.append("</div>")

    # -- errors ------------------------------------------------------------
    if result.errors:
        parts.append("<h2>Non-fatal issues</h2>")
        parts.append("<div class='panel'><ul>")
        for message in result.errors[:50]:
            parts.append(f"<li class='muted wrap-any'>{_esc(message)}</li>")
        parts.append("</ul></div>")

    parts.append(
        f"<footer>Generated by SUBDOMAINX v{_esc(__version__)} &middot; passive discovery only "
        "&middot; no exploitation, no credentials, no API keys.</footer>"
    )
    parts.append(f"<script>{_SCRIPT}</script>")
    parts.append("</div></body></html>")
    return "\n".join(parts)


def write_html(result: ScanResult, path: str) -> str:
    """Write the HTML report to ``path`` and return the document."""
    logger = get_logger()
    document = render_html(result)
    target = Path(path)
    if target.parent and str(target.parent) not in ("", "."):
        target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(document, encoding="utf-8")
    logger.info("HTML report written to %s", path)
    return document


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _card(label: str, value: Any) -> str:
    return f"<div class='card'><div class='k'>{_esc(label)}</div><div class='v'>{_esc(value)}</div></div>"


def _score_class(score: int) -> str:
    if score >= 95:
        return "s-very-high"
    if score >= 80:
        return "s-high"
    if score >= 60:
        return "s-medium"
    if score >= 30:
        return "s-low"
    return "s-very-low"


def _host_row(host: Host) -> str:
    dns = "yes" if host.dns_resolved else ("no" if host.dns else "-")
    status = host.http.status_code if host.http and host.http.status_code else "-"
    status_class = "ok" if isinstance(status, int) and status < 400 else (
        "warn" if isinstance(status, int) and status < 500 else "bad" if isinstance(status, int) else "muted"
    )
    return (
        f"<tr data-category='{_esc(host.category.value)}'>"
        f"<td class='host'>{_esc(host.host)}</td>"
        f"<td class='score {_score_class(host.confidence)}' data-sort='{host.confidence}'>"
        f"{host.confidence} <span class='muted'>{_esc(host.confidence_label.value)}</span></td>"
        f"<td data-sort='{host.source_count}'>{host.source_count} "
        f"<span class='muted'>{_esc(', '.join(host.sources[:4]))}</span></td>"
        f"<td>{dns}</td>"
        f"<td class='{status_class}'>{_esc(status)}</td>"
        f"<td class='muted'>{_esc(host.http.category.value if host.http else '')}</td>"
        f"<td class='wrap-any'>{_esc(truncate(host.title or '', 60))}</td>"
        f"<td class='wrap-any'>{_esc(', '.join(host.technology_names[:4]))}</td>"
        f"<td>{_esc(host.cdn.provider or '-')}</td>"
        f"<td>{_esc(host.category.value)}</td>"
        f"<td data-sort='{_esc(host.first_seen or '')}'>{_esc(host.first_seen or '-')}</td>"
        f"<td data-sort='{_esc(host.last_seen or '')}'>{_esc(host.last_seen or '-')}</td>"
        "</tr>"
    )


def _count(values: Sequence[Any]) -> List[tuple]:
    counter: Dict[str, int] = {}
    for value in values or []:
        if not value:
            continue
        counter[str(value)] = counter.get(str(value), 0) + 1
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))


def _tag_summary(title: str, items: Sequence[tuple]) -> str:
    tags = "".join(f"<span class='tag'>{_esc(name)} <strong>{count}</strong></span>" for name, count in items[:40])
    return f"<h3>{_esc(title)}</h3><div>{tags or '<span class=muted>none detected</span>'}</div>"


def _render_graph(graph: Dict[str, Any]) -> str:
    """Render a small, static SVG bipartite graph (sources on top, hosts below)."""
    nodes = graph.get("nodes") or []
    sources = [n for n in nodes if n.get("type") == "source"][:8]
    hosts = [n for n in nodes if n.get("type") == "host"][:18]
    if not sources or not hosts:
        return "<p class='muted'>Not enough data to render the correlation graph.</p>"

    width = 1000
    height = 420
    top_y = 60
    bottom_y = 340
    parts = [
        f"<svg viewBox='0 0 {width} {height}' role='img' aria-label='source correlation graph'>"
    ]

    def x_pos(index: int, count: int) -> float:
        if count <= 1:
            return width / 2
        margin = 80
        return margin + index * ((width - 2 * margin) / (count - 1))

    host_x = {h["id"]: x_pos(i, len(hosts)) for i, h in enumerate(hosts)}
    source_x = {s["id"]: x_pos(i, len(sources)) for i, s in enumerate(sources)}

    edges = graph.get("edges") or []
    host_ids = set(host_x)
    drawn = 0
    for edge in edges:
        source_id = f"source:{edge.get('source')}"
        host_id = f"host:{edge.get('host')}"
        if host_id not in host_ids or source_id not in source_x:
            continue
        x1, y1 = source_x[source_id], top_y
        x2, y2 = host_x[host_id], bottom_y
        parts.append(
            f"<line x1='{x1:.1f}' y1='{y1}' x2='{x2:.1f}' y2='{y2}' "
            f"stroke='#2b3242' stroke-width='1'/>"
        )
        drawn += 1
        if drawn > 400:
            break

    for source in sources:
        x = source_x[source["id"]]
        parts.append(f"<circle cx='{x:.1f}' cy='{top_y}' r='7' fill='#bc8cff'/>")
        parts.append(
            f"<text x='{x:.1f}' y='{top_y - 14}' fill='#e6edf3' font-size='11' "
            f"text-anchor='middle'>{_esc(source.get('label'))}</text>"
        )
    for host in hosts:
        x = host_x[host["id"]]
        radius = 4 + min(6, int(host.get("sources", 1)))
        parts.append(f"<circle cx='{x:.1f}' cy='{bottom_y}' r='{radius}' fill='#58a6ff'/>")
        label = str(host.get("label", ""))
        parts.append(
            f"<text x='{x:.1f}' y='{bottom_y + 22}' fill='#8b949e' font-size='9' "
            f"transform='rotate(35 {x:.1f} {bottom_y + 22})'>{_esc(truncate(label, 26))}</text>"
        )
    parts.append("</svg>")
    return "".join(parts)


def render_json_embed(data: Any) -> str:  # noqa: ANN401
    """Return a JSON value escaped for embedding inside a ``<script>`` block."""
    return json.dumps(data, default=str).replace("</", "<\\/")
