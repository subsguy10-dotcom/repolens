"""Local-only web dashboard with standard-library HTTP server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from pathlib import Path
import argparse
import json
from .scanner import analyze

DASHBOARD = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RepoLens | Repository Health</title><style>
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,sans-serif}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 80% 0%,#172554 0%,transparent 35%),#070b16;color:#f1f5f9}main{max-width:1080px;margin:auto;padding:52px 24px}.brand{color:#93c5fd;font-weight:800;letter-spacing:.12em}.sub{color:#94a3b8}.heading{font-size:clamp(30px,5vw,54px);letter-spacing:-.055em;margin:16px 0}.tag{border:1px solid #334155;border-radius:99px;padding:7px 12px;font-size:13px;color:#cbd5e1}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.grid{display:grid;grid-template-columns:1.5fr repeat(3,1fr);gap:14px;margin:32px 0}.card{background:#101a2d;border:1px solid #263551;border-radius:18px;padding:24px;box-shadow:0 14px 30px #0002}.label{color:#94a3b8;font-size:14px}.value{font-size:36px;font-weight:800;margin:10px 0}.score{font-size:72px;font-weight:850;color:#60a5fa}.issue{display:flex;gap:16px;border-top:1px solid #263551;padding:18px 0;align-items:start}.sev{font-size:11px;letter-spacing:.07em;padding:6px 8px;border-radius:6px;background:#334155}.high{background:#7f1d1d}.medium{background:#78350f}.low{background:#164e63}.muted{color:#94a3b8;font-size:13px;overflow-wrap:anywhere}.issue h3{margin:0 0 6px;font-size:16px}button{background:#2563eb;color:white;border:0;border-radius:10px;padding:10px 15px;cursor:pointer;font-weight:650}button:hover{background:#1d4ed8}@media(max-width:750px){.grid{grid-template-columns:repeat(2,1fr)}.grid .card:first-child{grid-column:span 2}}
</style></head><body><main><div class="top"><div class="brand">◈ REPOLENS <span class="tag">OPEN SOURCE</span></div><button id="export" disabled>Export JSON ↓</button></div><h1 class="heading">Understand your codebase.<br>Improve what matters.</h1><p class="sub">Local-first repository health checks • No API keys • No source upload</p><div class="grid"><section class="card"><div class="label">Health score</div><div id="score" class="score">—</div><div class="muted" id="name"></div></section><section class="card"><div class="label">Files</div><div id="files" class="value">—</div></section><section class="card"><div class="label">Code lines</div><div id="lines" class="value">—</div></section><section class="card"><div class="label">Findings</div><div id="count" class="value">—</div></section></div><section class="card"><h2>Actionable findings</h2><p class="sub">Potential issues found in this folder. These checks are intentionally limited and may produce false positives.</p><p id="warnings" role="status"></p><div id="findings" aria-live="polite">Scanning…</div></section><p class="muted" style="margin-top:25px">RepoLens v0.1 • Offline static checks • Not a security certification</p></main><script>
let report;async function load(){try{const r=await fetch('/api/report');if(!r.ok)throw Error('Request failed');report=await r.json();document.getElementById('export').disabled=false;document.getElementById('warnings').textContent=(report.warnings||[]).join(' ');document.getElementById('score').textContent=report.score+'/100';document.getElementById('name').textContent=report.name;document.getElementById('files').textContent=report.files;document.getElementById('lines').textContent=report.lines_of_code.toLocaleString();document.getElementById('count').textContent=report.findings.length;let el=document.getElementById('findings');el.replaceChildren();if(!report.findings.length){el.textContent='No issues flagged by implemented checks.';return;}for(const f of report.findings){let row=document.createElement('div');row.className='issue';let tag=document.createElement('span');tag.className='sev '+f.severity;tag.textContent=f.severity.toUpperCase();let detail=document.createElement('div');let h=document.createElement('h3');h.textContent=f.title;let p=document.createElement('p');p.textContent=f.detail;p.className='sub';let loc=document.createElement('div');loc.className='muted';loc.textContent=f.file?(f.file+(f.line?':'+f.line:'')):'';detail.append(h,p,loc);row.append(tag,detail);el.append(row)}}catch(e){document.getElementById('findings').textContent='Failed to scan: '+e.message}}document.getElementById('export').addEventListener('click',()=>{if(!report)return;let u=URL.createObjectURL(new Blob([JSON.stringify(report,null,2)],{type:'application/json'}));let a=document.createElement('a');a.href=u;a.download='repolens-report.json';a.click();URL.revokeObjectURL(u)});load();
</script></body></html>'''

def make_server(path: str, port: int):
    root = Path(path).expanduser().resolve()
    if not root.is_dir():
        raise ValueError('Repository path must be a directory')
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get('Host') not in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}:
                self.send_error(403); return
            uri = urlparse(self.path).path
            if uri == '/':
                payload = DASHBOARD.encode('utf-8'); content_type = 'text/html; charset=utf-8'
            elif uri == '/api/report':
                try:
                    payload = json.dumps(analyze(root)).encode('utf-8')
                except (OSError, ValueError):
                    self.send_error(500, 'Repository could not be scanned'); return
                content_type = 'application/json; charset=utf-8'
            else:
                self.send_error(404); return
            self.send_response(200); self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store'); self.send_header('X-Content-Type-Options', 'nosniff')
            self.end_headers(); self.wfile.write(payload)
    return ThreadingHTTPServer(('127.0.0.1', port), Handler)

def serve(path: str, port: int):
    with make_server(path, port) as server:
        print(f'RepoLens running at http://127.0.0.1:{port} (Ctrl+C to stop)')
        server.serve_forever()

def main():
    p = argparse.ArgumentParser(description='Launch RepoLens local dashboard')
    p.add_argument('path', nargs='?', default='.')
    p.add_argument('--port', type=int, default=8765)
    a = p.parse_args()
    if not 1 <= a.port <= 65535:
        p.error('--port must be between 1 and 65535')
    try:
        serve(a.path, a.port)
    except (OSError, ValueError) as error:
        p.error(str(error))
    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
