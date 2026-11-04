#!/usr/bin/env python3
"""Gera os cinco cadeados SVG do CODE SENTINEL (fundo transparente).

Uso:
    python3 scripts/make_padlocks.py [--out assets/padlocks]

Os SVGs sao a fonte da verdade. Os PNGs sao renderizados a partir deles por
scripts/render_padlocks.mjs (Playwright/Chromium) -- opcional, so para quem
quer regenerar os PNGs.

Linguagem visual compartilhada pelos 5 niveis:
  * mesma geometria de corpo/arco (o "cadeado" e sempre o mesmo objeto);
  * cor evolui de vermelho (risco) -> ambar -> azul aco -> verde -> ouro/ciano;
  * o arco evolui de aberto e torto -> levantado -> fechado -> reforcado -> duplo;
  * trilhas de circuito no corpo aumentam com o nivel (aparencia tecnologica);
  * 5 "pips" de progresso sob o cadeado, n preenchidos para o nivel n.
"""
from __future__ import annotations

import argparse
from pathlib import Path

W = H = 512
BODY = dict(x=116, y=236, w=280, h=220, r=40)

LEVELS = {
    1: dict(name="Codigo Exposto", c1="#ff6b6b", c2="#d7263d", c3="#6e0b1a",
            shackle="#9aa3ad", shackle_hi="#e3e8ee", accent="#ff4757"),
    2: dict(name="Protecao Fraca", c1="#ffd166", c2="#f39c12", c3="#8a4b00",
            shackle="#9aa3ad", shackle_hi="#e3e8ee", accent="#ffb020"),
    3: dict(name="Protecao Moderada", c1="#8fc1ff", c2="#3b82f6", c3="#1e3a8a",
            shackle="#a7b1bc", shackle_hi="#f1f5f9", accent="#60a5fa"),
    4: dict(name="Alta Integridade", c1="#6ff7c8", c2="#10b981", c3="#065f46",
            shackle="#b8c2cc", shackle_hi="#ffffff", accent="#34d399"),
    5: dict(name="Integridade Maxima", c1="#fff3b0", c2="#f5c542", c3="#8a5a00",
            shackle="#cfd8e3", shackle_hi="#ffffff", accent="#22d3ee"),
}


def defs(lv: int, p: dict) -> str:
    glow = ""
    if lv >= 4:
        std = 10 if lv == 4 else 16
        glow = f"""
    <filter id="glow" x="-30%" y="-30%" width="160%" height="160%">
      <feGaussianBlur stdDeviation="{std}" result="b"/>
      <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>"""
    return f"""
  <defs>
    <linearGradient id="body" x1="0" y1="0" x2="0.35" y2="1">
      <stop offset="0" stop-color="{p['c1']}"/>
      <stop offset="0.55" stop-color="{p['c2']}"/>
      <stop offset="1" stop-color="{p['c3']}"/>
    </linearGradient>
    <linearGradient id="shackle" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0" stop-color="{p['shackle']}"/>
      <stop offset="0.45" stop-color="{p['shackle_hi']}"/>
      <stop offset="1" stop-color="{p['shackle']}"/>
    </linearGradient>
    <linearGradient id="gloss" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#ffffff" stop-opacity="0.45"/>
      <stop offset="1" stop-color="#ffffff" stop-opacity="0"/>
    </linearGradient>
    <radialGradient id="aura" cx="0.5" cy="0.55" r="0.5">
      <stop offset="0" stop-color="{p['accent']}" stop-opacity="0.55"/>
      <stop offset="1" stop-color="{p['accent']}" stop-opacity="0"/>
    </radialGradient>
    <linearGradient id="gold" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#fff7cc"/>
      <stop offset="0.5" stop-color="#f5c542"/>
      <stop offset="1" stop-color="#a06a00"/>
    </linearGradient>{glow}
  </defs>"""


def shackle(lv: int) -> str:
    sw = {1: 34, 2: 34, 3: 36, 4: 44, 5: 46}[lv]
    if lv == 1:
        # aberto e torto: levantado e girado para fora
        d = "M176 262 V156 A80 80 0 0 1 336 156 V200"
        return (f'<g transform="rotate(-22 176 250)">'
                f'<path d="{d}" fill="none" stroke="#3b4148" stroke-width="{sw + 8}" stroke-linecap="round"/>'
                f'<path d="{d}" fill="none" stroke="url(#shackle)" stroke-width="{sw}" stroke-linecap="round"/></g>')
    if lv == 2:
        # destravado: levantado, perna direita fora do corpo
        d = "M176 262 V140 A80 80 0 0 1 336 140 V196"
        return (f'<path d="{d}" fill="none" stroke="#3b4148" stroke-width="{sw + 8}" stroke-linecap="round"/>'
                f'<path d="{d}" fill="none" stroke="url(#shackle)" stroke-width="{sw}" stroke-linecap="round"/>')
    d = "M176 262 V166 A80 80 0 0 1 336 166 V262"
    out = (f'<path d="{d}" fill="none" stroke="#2b3138" stroke-width="{sw + 8}" stroke-linecap="round"/>'
           f'<path d="{d}" fill="none" stroke="url(#shackle)" stroke-width="{sw}" stroke-linecap="round"/>')
    if lv >= 4:
        # anel de reforco nas pernas do arco
        for x in (176, 336):
            out += (f'<rect x="{x - sw / 2 - 5}" y="214" width="{sw + 10}" height="18" rx="5" '
                    f'fill="{"url(#gold)" if lv == 5 else "#5b6670"}" stroke="#1f252b" stroke-width="2"/>')
    if lv == 5:
        # nucleo luminoso dentro do arco (arco duplo)
        out += (f'<path d="{d}" fill="none" stroke="#22d3ee" stroke-width="6" stroke-linecap="round" '
                f'opacity="0.9" filter="url(#glow)"/>')
    return out


def body(lv: int, p: dict) -> str:
    b = BODY
    out = (f'<rect x="{b["x"]}" y="{b["y"]}" width="{b["w"]}" height="{b["h"]}" rx="{b["r"]}" '
           f'fill="url(#body)" stroke="{p["c3"]}" stroke-width="6"/>')
    # brilho superior
    out += (f'<rect x="{b["x"] + 14}" y="{b["y"] + 12}" width="{b["w"] - 28}" height="70" rx="28" '
            f'fill="url(#gloss)"/>')
    # trilhas de circuito: quantidade cresce com o nivel
    traces = [
        "M140 300 H190 L205 315 H232",
        "M372 300 H322 L307 315 H280",
        "M140 410 H180 L195 395 H222",
        "M372 410 H332 L317 395 H290",
        "M256 438 V418",
        "M150 355 H200",
        "M362 355 H312",
    ]
    n = {1: 1, 2: 2, 3: 3, 4: 5, 5: 7}[lv]
    col = "#ffffff" if lv < 5 else "#22d3ee"
    op = 0.35 if lv < 5 else 0.85
    for t in traces[:n]:
        out += f'<path d="{t}" fill="none" stroke="{col}" stroke-opacity="{op}" stroke-width="4" stroke-linecap="round"/>'
        end = t.split()[-1]
        # no terminal da trilha
        try:
            parts = t.replace("M", "").split()
            x0, y0 = parts[0], parts[1]
            out += f'<circle cx="{x0}" cy="{y0}" r="6" fill="{col}" fill-opacity="{op}"/>'
        except Exception:  # pragma: no cover - apenas decoracao
            pass
        del end
    if lv == 4:
        # faixas de reforco com rebites
        for y in (262, 430):
            out += f'<rect x="{b["x"] + 6}" y="{y - 6}" width="{b["w"] - 12}" height="12" rx="6" fill="#064e3b" opacity="0.55"/>'
            for x in (140, 196, 316, 372):
                out += f'<circle cx="{x}" cy="{y}" r="6" fill="#d1fae5" stroke="#064e3b" stroke-width="2"/>'
    if lv == 5:
        # moldura dourada dupla
        out += (f'<rect x="{b["x"] + 10}" y="{b["y"] + 10}" width="{b["w"] - 20}" height="{b["h"] - 20}" '
                f'rx="{b["r"] - 10}" fill="none" stroke="#fff3b0" stroke-opacity="0.8" stroke-width="3"/>')
        for x, y in ((140, 260), (372, 260), (140, 432), (372, 432)):
            out += f'<circle cx="{x}" cy="{y}" r="7" fill="url(#gold)" stroke="#5c3d00" stroke-width="2"/>'
    if lv == 1:
        # rachaduras
        out += ('<path d="M150 250 L176 300 L160 330 L190 372" fill="none" stroke="#2a0008" '
                'stroke-width="5" stroke-linecap="round" stroke-linejoin="round" opacity="0.75"/>'
                '<path d="M380 330 L350 352 L362 386 L336 420" fill="none" stroke="#2a0008" '
                'stroke-width="4" stroke-linecap="round" stroke-linejoin="round" opacity="0.65"/>')
    if lv == 2:
        out += ('<path d="M372 262 L352 296 L364 318" fill="none" stroke="#3d2200" '
                'stroke-width="4" stroke-linecap="round" stroke-linejoin="round" opacity="0.6"/>')
    return out


def emblem(lv: int, p: dict) -> str:
    cx, cy = 256, 348
    if lv == 1:
        # triangulo de alerta no lugar do segredo
        return (f'<path d="M{cx} {cy - 54} L{cx + 56} {cy + 44} H{cx - 56} Z" fill="#1a0006" '
                f'stroke="#ffd2d2" stroke-width="6" stroke-linejoin="round"/>'
                f'<rect x="{cx - 6}" y="{cy - 22}" width="12" height="40" rx="5" fill="#ffd2d2"/>'
                f'<circle cx="{cx}" cy="{cy + 30}" r="7" fill="#ffd2d2"/>')
    keyhole = (f'<circle cx="{cx}" cy="{cy - 12}" r="20" fill="#11161c"/>'
               f'<path d="M{cx - 10} {cy} L{cx - 16} {cy + 40} H{cx + 16} L{cx + 10} {cy} Z" fill="#11161c"/>')
    if lv in (2, 3):
        ring = "#3d2200" if lv == 2 else "#0b1f4d"
        return f'<circle cx="{cx}" cy="{cy}" r="46" fill="{ring}" fill-opacity="0.35"/>' + keyhole
    if lv == 4:
        shield = (f'M{cx} {cy - 64} L{cx + 54} {cy - 42} V{cy + 6} '
                  f'C{cx + 54} {cy + 40} {cx + 28} {cy + 60} {cx} {cy + 72} '
                  f'C{cx - 28} {cy + 60} {cx - 54} {cy + 40} {cx - 54} {cy + 6} V{cy - 42} Z')
        return (f'<path d="{shield}" fill="#053d2e" stroke="#d1fae5" stroke-width="5"/>'
                f'<g transform="translate(0 4) scale(1)">{keyhole}</g>')
    # nivel 5: hexagono dourado + check ciano
    import math
    pts = " ".join(f"{cx + 64 * math.cos(math.radians(a - 90)):.1f},{cy + 64 * math.sin(math.radians(a - 90)):.1f}"
                   for a in range(0, 360, 60))
    pts2 = " ".join(f"{cx + 50 * math.cos(math.radians(a - 90)):.1f},{cy + 50 * math.sin(math.radians(a - 90)):.1f}"
                    for a in range(0, 360, 60))
    return (f'<polygon points="{pts}" fill="url(#gold)" stroke="#5c3d00" stroke-width="4"/>'
            f'<polygon points="{pts2}" fill="#0b1220"/>'
            f'<path d="M{cx - 24} {cy + 2} L{cx - 6} {cy + 22} L{cx + 28} {cy - 18}" fill="none" '
            f'stroke="#22d3ee" stroke-width="10" stroke-linecap="round" stroke-linejoin="round" filter="url(#glow)"/>')


def extras(lv: int, p: dict) -> str:
    out = ""
    if lv >= 4:
        out += f'<ellipse cx="256" cy="330" rx="230" ry="210" fill="url(#aura)"/>'
    if lv == 5:
        # orbita e brilhos
        out += ('<ellipse cx="256" cy="332" rx="222" ry="70" fill="none" stroke="#22d3ee" stroke-width="3" '
                'stroke-opacity="0.55" transform="rotate(-14 256 332)" stroke-dasharray="14 10"/>')
        for x, y, s in ((70, 150, 16), (446, 120, 20), (440, 470, 12), (84, 444, 10), (400, 214, 9)):
            out += (f'<path d="M{x} {y - s} Q{x} {y} {x + s} {y} Q{x} {y} {x} {y + s} Q{x} {y} {x - s} {y} '
                    f'Q{x} {y} {x} {y - s} Z" fill="#fff7cc"/>')
    if lv == 1:
        # fragmentos "glitch" se soltando
        for x, y, w in ((70, 300, 26), (420, 380, 20), (446, 300, 12), (60, 400, 14)):
            out += f'<rect x="{x}" y="{y}" width="{w}" height="8" rx="2" fill="#ff4757" opacity="0.7"/>'
    return out


def pips(lv: int, p: dict) -> str:
    out = ""
    for i in range(5):
        x = 256 + (i - 2) * 34
        filled = i < lv
        fill = p["accent"] if filled else "none"
        out += (f'<rect x="{x - 12}" y="478" width="24" height="10" rx="5" fill="{fill}" '
                f'stroke="{p["accent"]}" stroke-width="2.5" stroke-opacity="{1 if filled else 0.5}"/>')
    return out


def build(lv: int) -> str:
    p = LEVELS[lv]
    title = f"CODE SENTINEL - Nivel {lv}: {p['name']}"
    return f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" role="img" aria-label="{title}">
  <title>{title}</title>{defs(lv, p)}
  {extras(lv, p)}
  <g filter="{'url(#glow)' if lv == 5 else 'none'}" >{shackle(lv)}</g>
  <ellipse cx="256" cy="462" rx="140" ry="10" fill="#000" opacity="0.18"/>
  {body(lv, p)}
  {emblem(lv, p)}
  {pips(lv, p)}
</svg>
"""


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "assets" / "padlocks"))
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    for lv in LEVELS:
        f = out / f"level-{lv}.svg"
        f.write_text(build(lv), encoding="utf-8")
        print(f"gerado {f}")


if __name__ == "__main__":
    main()
