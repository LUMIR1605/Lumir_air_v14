"""Private graph exports and dependency-free offline HTML viewer."""

from html import escape
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Mapping


class GraphExporter:
    def export_all(self, *, snapshot: Mapping[str, object], directory: Path) -> dict[str, str]:
        target = Path(directory).resolve()
        target.mkdir(parents=True, exist_ok=True)
        json_path = target / "graph.json"
        graphml_path = target / "graph.graphml"
        viewer_path = target / "graph_viewer.html"
        self._atomic(json_path, json.dumps(snapshot, ensure_ascii=False, indent=2, sort_keys=True).encode() + b"\n")
        self._atomic(graphml_path, self._graphml(snapshot).encode("utf-8"))
        self._atomic(viewer_path, self._viewer(snapshot).encode("utf-8"))
        return {"json_path": str(json_path), "graphml_path": str(graphml_path),
                "viewer_path": str(viewer_path),
                "json_sha256": hashlib.sha256(json_path.read_bytes()).hexdigest(),
                "graphml_sha256": hashlib.sha256(graphml_path.read_bytes()).hexdigest(),
                "viewer_sha256": hashlib.sha256(viewer_path.read_bytes()).hexdigest()}

    @staticmethod
    def _graphml(snapshot: Mapping[str, object]) -> str:
        nodes = []
        for item in snapshot.get("nodes", ()):
            evidence = ",".join(str(value) for value in item.get("evidence_refs", ()))
            nodes.append(
                f'<node id="{escape(str(item["entity_id"]), quote=True)}">'
                f'<data key="type">{escape(str(item["entity_type"]))}</data>'
                f'<data key="label">{escape(str(item["display_value"]))}</data>'
                f'<data key="confidence">{escape(str(item["confidence"]))}</data>'
                f'<data key="status">{escape(str(item["status"]))}</data>'
                f'<data key="evidence_refs">{escape(evidence)}</data></node>'
            )
        edges = []
        for item in snapshot.get("edges", ()):
            evidence = ",".join(str(value) for value in item.get("evidence_refs", ()))
            edges.append(
                f'<edge id="{escape(str(item["relation_id"]), quote=True)}" '
                f'source="{escape(str(item["source_entity_id"]), quote=True)}" '
                f'target="{escape(str(item["target_entity_id"]), quote=True)}">'
                f'<data key="type">{escape(str(item["relation_type"]))}</data>'
                f'<data key="confidence">{escape(str(item["confidence"]))}</data>'
                f'<data key="status">{escape(str(item["status"]))}</data>'
                f'<data key="evidence_refs">{escape(evidence)}</data></edge>'
            )
        keys = "".join(
            f'<key id="{key}" for="all" attr.name="{key}" attr.type="string"/>'
            for key in ("type", "label", "confidence", "status", "evidence_refs")
        )
        return ('<?xml version="1.0" encoding="UTF-8"?>\n'
                '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">'
                f'{keys}<graph id="G" edgedefault="directed">{"".join(nodes)}{"".join(edges)}'
                '</graph></graphml>\n')

    @staticmethod
    def _viewer(snapshot: Mapping[str, object]) -> str:
        safe_payload = json.dumps({"nodes": snapshot.get("nodes", ()), "edges": snapshot.get("edges", ())},
                                  ensure_ascii=False).replace("<", "\\u003c")
        return f'''<!doctype html><html lang="pl"><head><meta charset="utf-8"><title>LUMIR Graph</title>
<style>body{{font:14px system-ui;background:#0d1726;color:#eef;padding:20px}}svg{{background:#15243a;width:100%;height:520px}}
.node{{cursor:pointer;fill:#60a5fa}}line{{stroke:#8ba0bd}}#detail{{white-space:pre-wrap;background:#15243a;padding:12px}}</style></head>
<body><h1>Graf sprawy</h1><svg id="graph" viewBox="0 0 1000 520"></svg><h2>Szczegóły</h2><pre id="detail">Kliknij encję.</pre>
<script>const data={safe_payload};const svg=document.getElementById('graph'), detail=document.getElementById('detail');
const ns='http://www.w3.org/2000/svg', pos={{}};data.nodes.forEach((n,i)=>{{const a=2*Math.PI*i/Math.max(1,data.nodes.length);pos[n.entity_id]=[500+380*Math.cos(a),260+210*Math.sin(a)]}});
data.edges.forEach(e=>{{const l=document.createElementNS(ns,'line'),a=pos[e.source_entity_id],b=pos[e.target_entity_id];if(!a||!b)return;l.setAttribute('x1',a[0]);l.setAttribute('y1',a[1]);l.setAttribute('x2',b[0]);l.setAttribute('y2',b[1]);l.onclick=()=>detail.textContent=JSON.stringify({{relation:e.relation_type,confidence:e.confidence,status:e.status,evidence_refs:e.evidence_refs}},null,2);svg.appendChild(l)}});
data.nodes.forEach(n=>{{const [x,y]=pos[n.entity_id],g=document.createElementNS(ns,'g'),c=document.createElementNS(ns,'circle'),t=document.createElementNS(ns,'text');c.setAttribute('cx',x);c.setAttribute('cy',y);c.setAttribute('r',18);c.setAttribute('class','node');t.setAttribute('x',x+22);t.setAttribute('y',y+5);t.setAttribute('fill','#eef');t.textContent=n.entity_type;g.append(c,t);g.onclick=()=>detail.textContent=JSON.stringify({{type:n.entity_type,value:n.display_value,confidence:n.confidence,status:n.status,evidence_refs:n.evidence_refs}},null,2);svg.appendChild(g)}});</script></body></html>'''

    @staticmethod
    def _atomic(path: Path, content: bytes) -> None:
        descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
