#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 reports/*.md 转成适合手机浏览的静态网页，可选整页加密。

设计要点：
- 手机优先：响应式、大字号、支持深色模式、红涨绿跌（A 股习惯）。
- 零额外依赖：markdown2 已在 requirements.txt 中；缺失时回退到内置简易转换。
- 可选加密：设置环境变量 REPORT_PASSWORD 后，整页内容用 PBKDF2 + 流密码加密，
  浏览器端用 Web Crypto 解密。因为 GitHub Pages 页面是公开可访问的，
  强烈建议设置密码，避免自选股与持仓观点泄露。
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

DATE_RE = re.compile(r"(?:report|market_review)_(\d{8})(?:_(\w+))?\.md$")
DEFAULT_TITLE = "股票分析日报"


# --------------------------------------------------------------------------
# Markdown -> HTML
# --------------------------------------------------------------------------
def _fallback_md_to_html(text: str) -> str:
    """极简 Markdown 转换（标题/表格/列表/粗体/引用/代码块）。"""
    lines = text.split("\n")
    out: list[str] = []
    in_code = False
    in_list = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip().startswith("```"):
            out.append("</pre>" if in_code else "<pre>")
            in_code = not in_code
            i += 1
            continue
        if in_code:
            out.append(line.replace("&", "&amp;").replace("<", "&lt;"))
            i += 1
            continue
        if line.lstrip().startswith("|") and i + 1 < len(lines) and re.match(r"^\s*\|[\s:|-]+\|\s*$", lines[i + 1]):
            header = [c.strip() for c in line.strip().strip("|").split("|")]
            i += 2
            rows = []
            while i < len(lines) and lines[i].lstrip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            out.append("<table><thead><tr>" + "".join(f"<th>{c}</th>" for c in header) + "</tr></thead><tbody>")
            for r in rows:
                out.append("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>")
            out.append("</tbody></table>")
            continue
        m = re.match(r"^(#{1,6})\s+(.*)$", line)
        if m:
            if in_list:
                out.append("</ul>")
                in_list = False
            lv = len(m.group(1))
            out.append(f"<h{lv}>{m.group(2).strip()}</h{lv}>")
            i += 1
            continue
        if re.match(r"^\s*[-*+]\s+", line):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append("<li>" + re.sub(r"^\s*[-*+]\s+", "", line) + "</li>")
            i += 1
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if line.strip() in {"---", "***"}:
            out.append("<hr>")
            i += 1
            continue
        if line.strip():
            body = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", line)
            body = re.sub(r"`(.+?)`", r"<code>\1</code>", body)
            if line.lstrip().startswith(">"):
                out.append("<blockquote>" + body.lstrip("> ").strip() + "</blockquote>")
            else:
                out.append("<p>" + body + "</p>")
        i += 1
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def md_to_html(text: str) -> str:
    try:
        import markdown2  # type: ignore
        return markdown2.markdown(text, extras=["tables", "fenced-code-blocks", "break-on-newline"])
    except Exception:
        return _fallback_md_to_html(text)


# --------------------------------------------------------------------------
# 可选加密（PBKDF2 + XOR 流密码）
# --------------------------------------------------------------------------
def _keystream(key: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:length])


def encrypt_text(plain: str, password: str) -> dict:
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000, dklen=32)
    data = plain.encode("utf-8")
    ct = bytes(a ^ b for a, b in zip(data, _keystream(key, len(data))))
    return {
        "v": 1,
        "salt": base64.b64encode(salt).decode(),
        "ct": base64.b64encode(ct).decode(),
    }


# --------------------------------------------------------------------------
# 页面外壳
# --------------------------------------------------------------------------
CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1a1d21;--muted:#6b7280;--line:#e5e7eb;--up:#d92b2b;--down:#0f9d58;--accent:#2563eb}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--card:#1c2024;--fg:#e8eaed;--muted:#9aa0a6;--line:#2c3136;--up:#ff6b6b;--down:#3ddc84;--accent:#60a5fa}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"PingFang SC","Microsoft YaHei",sans-serif;
 font-size:16px;line-height:1.75;-webkit-text-size-adjust:100%}
.wrap{max-width:820px;margin:0 auto;padding:16px 14px 56px}
header{position:sticky;top:0;background:var(--bg);padding:12px 0 8px;border-bottom:1px solid var(--line);margin-bottom:14px}
h1{font-size:20px;margin:0}
.sub{color:var(--muted);font-size:13px;margin-top:4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin-bottom:12px}
.card h2{font-size:17px;margin:0 0 6px}
.card p{margin:6px 0;color:var(--muted);font-size:14px}
a{color:var(--accent);text-decoration:none}
table{width:100%;border-collapse:collapse;margin:12px 0;font-size:14px;display:block;overflow-x:auto;white-space:nowrap}
th,td{border:1px solid var(--line);padding:7px 9px;text-align:left}
th{background:rgba(128,128,128,.08)}
h2{font-size:19px;margin-top:26px}h3{font-size:16px;margin-top:20px}
blockquote{margin:10px 0;padding:8px 12px;border-left:3px solid var(--accent);background:rgba(128,128,128,.06);color:var(--fg)}
pre{background:rgba(128,128,128,.1);padding:10px;border-radius:8px;overflow-x:auto;font-size:13px}
code{font-size:13px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;border:1px solid var(--line);color:var(--muted)}
.gate{max-width:420px;margin:14vh auto;text-align:center}
.gate input{width:100%;padding:12px;font-size:16px;border:1px solid var(--line);border-radius:10px;background:var(--card);color:var(--fg);margin-top:10px}
.gate button{margin-top:12px;width:100%;padding:12px;font-size:16px;border:0;border-radius:10px;background:var(--accent);color:#fff}
.err{color:var(--up);font-size:13px;margin-top:10px;min-height:18px}
"""

GATE_JS = """
async function _derive(pw, salt){
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({name:'PBKDF2', salt: salt, iterations:100000, hash:'SHA-256'}, base, 256);
  return new Uint8Array(bits);
}
async function _ks(key, len){
  const out = new Uint8Array(len); let off = 0, c = 0;
  const cb = new Uint8Array(8);
  while(off < len){
    cb.set([0,0,0,0,0,0,(c>>>8)&255,c&255], 6);
    const buf = new Uint8Array(key.length + 8); buf.set(key,0); buf.set(cb, key.length);
    const d = new Uint8Array(await crypto.subtle.digest('SHA-256', buf));
    const n = Math.min(d.length, len - off); out.set(d.subarray(0,n), off); off += n; c++;
  }
  return out;
}
function _b64(s){ return Uint8Array.from(atob(s), ch => ch.charCodeAt(0)); }
async function unlock(){
  const err = document.getElementById('err'); err.textContent = '';
  try{
    const pw = document.getElementById('pw').value;
    if(!pw){ err.textContent = '请输入密码'; return; }
    const payload = JSON.parse(document.getElementById('blob').textContent);
    const key = await _derive(pw, _b64(payload.salt));
    const ct = _b64(payload.ct);
    const ks = await _ks(key, ct.length);
    const pt = new Uint8Array(ct.length);
    for(let i=0;i<ct.length;i++) pt[i] = ct[i] ^ ks[i];
    const html = new TextDecoder().decode(pt);
    if(!html.includes('__DSA_OK__')){ err.textContent = '密码错误'; return; }
    document.getElementById('app').innerHTML = html;
    document.getElementById('gate').style.display = 'none';
    document.getElementById('app').style.display = 'block';
    try{ sessionStorage.setItem('dsa_pw', pw); }catch(e){}
    paint();
  }catch(e){ err.textContent = '解密失败：' + e; }
}
function paint(){
  document.querySelectorAll('td,th').forEach(td=>{
    const t = (td.textContent||'').trim();
    const m = t.match(/^([+-])\\d+(\\.\\d+)?%?$/);
    if(m){ td.style.color = m[1] === '-' ? 'var(--down)' : 'var(--up)'; td.style.fontWeight='600'; }
  });
}
document.getElementById('go').addEventListener('click', unlock);
document.getElementById('pw').addEventListener('keydown', e=>{ if(e.key==='Enter') unlock(); });
window.addEventListener('load', ()=>{ try{ const s = sessionStorage.getItem('dsa_pw'); if(s){ document.getElementById('pw').value = s; unlock(); } }catch(e){} });
"""


def shell(title: str, body_html: str, encrypted: dict | None, home: bool = False) -> str:
    nav = "" if home else '<div class="sub"><a href="index.html">← 返回报告列表</a></div>'
    if encrypted:
        blob = json.dumps(encrypted)
        return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>{title}</title><style>{CSS}</style></head><body>
<div class="gate" id="gate">
  <h1>🔒 {DEFAULT_TITLE}</h1>
  <div class="sub">输入查看密码</div>
  <input id="pw" type="password" placeholder="密码" autocomplete="current-password">
  <button id="go">解锁</button>
  <div class="err" id="err"></div>
</div>
<div class="wrap" id="app" style="display:none"></div>
<script type="application/json" id="blob">{blob}</script>
<script>{GATE_JS}</script></body></html>"""
    warn = ""
    if home:
        warn = ('<div class="warn">⚠️ 当前未加密，任何拿到网址的人都能看到你的自选股。'
                '在仓库 Settings → Secrets 里添加 <b>REPORT_PASSWORD</b> 即可启用密码。</div>')
    return f"""<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="robots" content="noindex,nofollow">
<title>{title}</title><style>{CSS}{WARN_CSS}</style></head><body>
<div class="wrap"><header><h1>{title}</h1>{nav}</header>{warn}{body_html}</div>
<script>{PAINT_JS}</script></body></html>"""


WARN_CSS = """
.warn{background:#fff4e5;border:1px solid #ffd8a8;color:#8a4b00;border-radius:10px;
 padding:10px 12px;font-size:13px;margin-bottom:12px;line-height:1.6}
@media (prefers-color-scheme:dark){.warn{background:#3a2a12;border-color:#6b4a1a;color:#ffd8a8}}
"""

PAINT_JS = """
(function(){
  document.querySelectorAll('td,th').forEach(function(td){
    var t=(td.textContent||'').trim();
    var m=t.match(/^([+-])\\d+(\\.\\d+)?%?$/);
    if(m){ td.style.color = m[1]==='-' ? 'var(--down)' : 'var(--up)'; td.style.fontWeight='600'; }
  });
})();
"""


# --------------------------------------------------------------------------
# 构建
# --------------------------------------------------------------------------
def collect(reports_dir: Path) -> dict:
    """返回 {date: {'market': Path|None, 'stocks': Path|None, 'per_stock': {code: Path}}}"""
    data: dict[str, dict] = {}
    for f in sorted(reports_dir.glob("*.md")):
        m = DATE_RE.search(f.name)
        if not m:
            continue
        date, code = m.group(1), m.group(2)
        entry = data.setdefault(date, {"market": None, "stocks": None, "per_stock": {}})
        if f.name.startswith("market_review_"):
            entry["market"] = f
        elif code:
            entry["per_stock"][code] = f
        else:
            entry["stocks"] = f
    return dict(sorted(data.items(), reverse=True))


def fmt_date(d: str) -> str:
    try:
        return datetime.strptime(d, "%Y%m%d").strftime("%Y年%m月%d日")
    except Exception:
        return d


def build(reports_dir: Path, out_dir: Path, password: str = "", title: str = DEFAULT_TITLE) -> int:
    data = collect(reports_dir)
    if not data:
        print("⚠️ reports/ 下没有找到报告文件", file=sys.stderr)
        return 0

    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True)

    def emit(filename: str, page_title: str, body: str, home: bool = False) -> None:
        if password:
            (out_dir / filename).write_text(
                shell(page_title, "", encrypt_text(body + "<!--__DSA_OK__-->", password), home=home),
                encoding="utf-8")
        else:
            (out_dir / filename).write_text(shell(page_title, body, None, home=home), encoding="utf-8")

    # 首页：日期列表
    cards = []
    for date, e in data.items():
        links = []
        if e["market"]:
            links.append(f'<a href="market_{date}.html">📊 大盘复盘</a>')
        if e["stocks"]:
            links.append(f'<a href="stocks_{date}.html">📈 个股分析汇总</a>')
        for code in sorted(e["per_stock"]):
            links.append(f'<a href="stock_{date}_{code}.html">🔎 {code}</a>')
        if not links:
            continue
        cards.append(
            f'<div class="card"><h2>{fmt_date(date)}</h2>'
            f'<p>{" · ".join(links)}</p></div>')
    index_body = f"<header><h1>{title}</h1><div class='sub'>共 {len(cards)} 个交易日 · 手机可直接浏览</div></header>" + "".join(cards)
    emit("index.html", title, index_body, home=True)

    count = 1
    for date, e in data.items():
        head = f"<header><h1>📊 大盘复盘</h1><div class='sub'>{fmt_date(date)}</div>" \
               f"<div class='sub'><a href='index.html'>← 返回报告列表</a></div></header>"
        if e["market"]:
            emit(f"market_{date}.html", f"大盘复盘 {date}",
                 head + md_to_html(e["market"].read_text(encoding="utf-8", errors="replace")))
            count += 1
        tail = f"<header><h1>📈 个股分析</h1><div class='sub'>{fmt_date(date)}</div>" \
               f"<div class='sub'><a href='index.html'>← 返回报告列表</a></div></header>"
        if e["stocks"]:
            emit(f"stocks_{date}.html", f"个股分析 {date}",
                 tail + md_to_html(e["stocks"].read_text(encoding="utf-8", errors="replace")))
            count += 1
        for code, path in sorted(e["per_stock"].items()):
            h = f"<header><h1>🔎 {code}</h1><div class='sub'>{fmt_date(date)}</div>" \
                f"<div class='sub'><a href='index.html'>← 返回报告列表</a></div></header>"
            emit(f"stock_{date}_{code}.html", f"{code} {date}",
                 h + md_to_html(path.read_text(encoding="utf-8", errors="replace")))
            count += 1

    print(f"✅ 已生成 {count} 个页面 → {out_dir}")
    print(f"   日期数：{len(data)}｜加密：{'是' if password else '否'}")
    return count


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    ap.add_argument("--out", default="pages")
    ap.add_argument("--title", default=os.getenv("REPORT_TITLE", DEFAULT_TITLE))
    args = ap.parse_args()

    password = os.getenv("REPORT_PASSWORD", "").strip()
    return 0 if build(Path(args.reports), Path(args.out), password, args.title) else 1


if __name__ == "__main__":
    sys.exit(main())
