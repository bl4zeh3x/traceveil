"""Produce a standalone report exclusively from sanitized data."""

from html import escape
from .core import sanitize


def render_report(document):
    entries = sanitize(document)["log"]["entries"]
    rows = []
    for index, entry in enumerate(entries, 1):
        req, res = entry["request"], entry["response"]
        cells = [index, req["method"], req["url"], res["status"],
                 entry["time"], res["content"]["size"], res["content"]["mimeType"]]
        rows.append("<tr>" + "".join(f"<td>{escape(str(v))}</td>" for v in cells) + "</tr>")
    return """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Traceveil · sanitized network review</title><style>
body{font:16px system-ui;background:#101b2b;color:#e9eff9;max-width:1100px;margin:3rem auto;padding:0 1.5rem}
h1{font-size:3rem;margin-bottom:.25rem}p{line-height:1.6;color:#c1cee0}.tag{color:#7ce1c1}
.table{overflow:auto}table{width:100%;border-collapse:collapse;font-size:.875rem}
th,td{text-align:left;border-bottom:1px solid #344259;padding:1rem .65rem;white-space:nowrap}
th{color:#7ce1c1}footer{margin-top:2rem;color:#a2b1c9}</style>
<p class="tag">LOCAL ONLY / CONSERVATIVE EXPORT</p><h1>Traceveil</h1>
<p>Network evidence without the original payloads. Hosts and routes below are pseudonyms;
headers, cookies, query values, request bodies and response text have been removed.</p>
""" + f"<p>{len(entries)} requests · No scripts, fonts, analytics or external assets.</p>" + """
<div class="table"><table><thead><tr><th>#</th><th>Method</th><th>Endpoint label</th>
<th>Status</th><th>Time (ms)</th><th>Size (bytes)</th><th>MIME type</th></tr></thead>
<tbody>""" + "".join(rows) + """</tbody></table></div>
<footer>Timing, sizes and relationships can still be identifying. Review before sharing.
Traceveil does not certify anonymity.</footer></html>"""
