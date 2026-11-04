"""Decoy document canaries — PDF/HTML with web-bug callbacks to Mirage beacons.

Generates lightweight files that, when opened in a browser-capable viewer,
issue an HTTP GET to the beacon listener (attacker IP + context).
True binary DOCX is represented as HTML/PDF decoys deployable as bait.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List


def _token() -> str:
    return uuid.uuid4().hex[:16]


def generate_document_canaries(
    org: str = "Company",
    beacon_base: str = "http://127.0.0.1:8888",
) -> List[Dict[str, Any]]:
    org = org or "Company"
    base = (beacon_base or "http://127.0.0.1:8888").rstrip("/")
    tid1, tid2 = _token(), _token()

    passwords_html = f"""<!DOCTYPE html>
<html><head><title>{org} — Passwords 2026</title>
<meta charset="utf-8">
</head><body>
<h1>{org} Password Vault Export</h1>
<p><em>Confidential — authorized staff only</em></p>
<table border="1" cellpadding="4">
<tr><th>System</th><th>User</th><th>Password</th></tr>
<tr><td>ERP</td><td>admin</td><td>Pr0d_S3cure_2026!</td></tr>
<tr><td>VPN</td><td>jsmith</td><td>ChangeMeImmediately!</td></tr>
<tr><td>AWS</td><td>deploy</td><td>AKIADECOY...</td></tr>
</table>
<!-- web-bug canary -->
<img src="{base}/t/{tid1}.gif?doc=Passwords_2026" width="1" height="1" alt=""/>
<iframe src="{base}/t/{tid1}?src=passwords_doc" width="0" height="0" style="display:none"></iframe>
</body></html>
"""

    # Minimal valid-ish PDF with URI annotation pointing at beacon (many viewers fetch)
    # Simple PDF: open action is not always honored; include URI as plain text + comment
    pdf_body = f"""%PDF-1.4
1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj
2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj
3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj
4 0 obj<< /Length 120 >>stream
BT /F1 12 Tf 50 700 Td ({org} Network Topology - CONFIDENTIAL) Tj 0 -20 Td
(See internal share Backups) Tj ET
endstream
endobj
5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000266 00000 n 
0000000438 00000 n 
trailer<< /Size 6 /Root 1 0 R >>
startxref
510
%%EOF
%% CANARY {base}/t/{tid2}?doc=Network_Topology
"""

    topology_html = f"""<!DOCTYPE html>
<html><head><title>{org} Network Topology</title></head><body>
<h1>{org} — Network Topology (Internal)</h1>
<pre>
[Internet]--[FW]--[Core]--[Servers]
                    |
              [Backup-Vault]
</pre>
<p>Full diagram: \\files-01\IT\topology.vsdx</p>
<img src="{base}/t/{tid2}.gif?doc=Network_Topology" width="1" height="1"/>
</body></html>
"""

    return [
        {
            "name": "passwords_2026_html",
            "relpath": "finance/Passwords_2026.html",
            "content": passwords_html,
            "beacon_token_ids": [tid1],
        },
        {
            "name": "passwords_2026_docx_note",
            "relpath": "finance/Passwords_2026.docx.txt",
            "content": (
                f"{org} Password export (open Passwords_2026.html in browser for formatted view)\n"
                f"Callback: {base}/t/{tid1}\n# DECOY DOCUMENT CANARY\n"
            ),
            "beacon_token_ids": [tid1],
        },
        {
            "name": "network_topology_pdf",
            "relpath": "it/Network_Topology.pdf",
            "content": pdf_body,
            "beacon_token_ids": [tid2],
        },
        {
            "name": "network_topology_html",
            "relpath": "it/Network_Topology.html",
            "content": topology_html,
            "beacon_token_ids": [tid2],
        },
    ]
