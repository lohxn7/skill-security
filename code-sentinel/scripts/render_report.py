#!/usr/bin/env python3
"""Gera o relatório final do CODE SENTINEL em Markdown e HTML (autocontido).

Uso:
    python3 scripts/render_report.py <projeto> [--out DIR] [--format md,html]

Lê stack.json, score.json, findings-merged.json e evidence/ do diretório de saída.
Escreve report.md (+ padlock-level-N.png ao lado) e report.html (cadeado SVG embutido).
Notas da revisão manual (resumo executivo) vêm de evidence/manual.json -> "summary".
"""
from __future__ import annotations

import argparse
import html
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (CATEGORIES, CATEGORY_PT, SEVERITY_PT, STATUS_PT, load_json, out_dir)  # noqa: E402

SKILL_DIR = Path(__file__).resolve().parent.parent
PADLOCKS = SKILL_DIR / "assets" / "padlocks"
VERSION = "1.0.0"
TOOL_STATUS_PT = {"executed": "executada", "failed": "falhou", "not_installed": "não instalada",
                  "skipped": "não executada", "not_applicable": "não se aplica"}
SEV_COLOR = {"CRITICAL": "#d7263d", "HIGH": "#f0700c", "MEDIUM": "#d4a106", "LOW": "#3b82f6", "INFO": "#6b7280"}


def load(d: Path) -> dict:
    ev = {p.stem: load_json(p, {}) for p in (d / "evidence").glob("*.json")}
    return {
        "stack": load_json(d / "stack.json", {}) or {},
        "score": load_json(d / "score.json", None),
        "findings": (load_json(d / "findings-merged.json", {}) or {}).get("findings", []),
        "tools": (ev.get("tools") or {}).get("tools", []),
        "evidence": ev,
        "manual": ev.get("manual") or {},
    }


def md_cell(s) -> str:
    return str(s if s is not None else "-").replace("|", "\\|").replace("\n", " ")


def tool_rows(data: dict) -> list[tuple]:
    rows = []
    for name in ("pattern-scan", "secret-scan"):
        e = data["evidence"].get(name)
        if e:
            rows.append((e.get("tool", name), e.get("version", ""), "executada",
                         ", ".join(e.get("checks", [])), f"{e.get('files_scanned', 0)} arquivos, {e.get('findings', 0)} achados"))
    for t in data["tools"]:
        rows.append((t["tool"], t.get("version") or "-", TOOL_STATUS_PT.get(t["status"], t["status"]),
                     ", ".join(t.get("intended_checks", [])),
                     t.get("reason") or (f"{t.get('findings', 0)} achados" if "findings" in t else "")))
    m = data["manual"]
    if m.get("checks"):
        rows.append(("Revisão manual (Claude)", "-", "executada", ", ".join(m["checks"]), m.get("scope", "")))
    return rows


def finding_md(i: int, f: dict) -> str:
    loc = f"`{f.get('file')}:{f.get('line')}`"
    lines = [
        f"#### {i}. [{SEVERITY_PT[f['severity']]}] {f['title']}",
        "",
        "| Campo | Detalhe |", "|---|---|",
        f"| **Arquivo / localização** | {loc} |",
        f"| **Gravidade** | {SEVERITY_PT[f['severity']]} |",
        f"| **Classificação** | {STATUS_PT.get(f['status'], f['status'])} |",
        f"| **Categoria** | {CATEGORY_PT.get(f['category'], f['category'])} |",
        f"| **Probabilidade** | {md_cell(f.get('likelihood'))} |",
        f"| **Origem** | {md_cell(', '.join([f.get('source', '')] + f.get('also_reported_by', [])))} |",
    ]
    if f.get("cwe") or f.get("owasp"):
        lines.append(f"| **Referência** | {md_cell(' · '.join(x for x in (f.get('cwe'), f.get('owasp')) if x))} |")
    lines += ["", f"**O que está acontecendo:** {f.get('description', '')}", "",
              f"**Como pode quebrar o sistema:** {f.get('failure_mode', '')}", "",
              f"**Impacto potencial:** {f.get('impact') or f.get('failure_mode', '')}", "",
              f"**Sugestão de correção:** {f.get('fix', '')}", ""]
    if f.get("evidence"):
        lines += ["**Evidência:**", "", "```", str(f["evidence"]).replace("```", "'''"), "```", ""]
    if f.get("fixed_code"):
        lines += ["**Código corrigido / exemplo:**", "", "```", f["fixed_code"].replace("```", "'''"), "```", ""]
    return "\n".join(lines)


def recommendations(findings: list[dict]) -> list[str]:
    out = []
    groups = [("P0 — imediato (bloqueia homologação/produção)", lambda f: f["severity"] == "CRITICAL"),
              ("P1 — antes de produção", lambda f: f["severity"] == "HIGH"),
              ("P2 — próximo ciclo", lambda f: f["severity"] == "MEDIUM"),
              ("P3 — melhoria contínua", lambda f: f["severity"] in ("LOW", "INFO"))]
    for title, pred in groups:
        items = [f for f in findings if pred(f)]
        if not items:
            continue
        seen, uniq = set(), []
        for f in items:
            k = f.get("rule_id") or f["title"]
            if k in seen:
                continue
            seen.add(k)
            n = sum(1 for g in items if (g.get("rule_id") or g["title"]) == k)
            uniq.append(f"- {f['title']}{f' ({n} ocorrências)' if n > 1 else ''}: {f.get('fix', '')}")
        out.append(f"**{title}**\n\n" + "\n".join(uniq[:15]))
    return out


def build_md(data: dict, padlock_rel: str) -> str:
    s, st, fs = data["score"], data["stack"], data["findings"]
    t = s["tests"]
    sec = [f for f in fs if f["category"] == "security"]
    perf = [f for f in fs if f["category"] == "performance"]
    L = [f"# CODE SENTINEL — RELATÓRIO DE INTEGRIDADE", "",
         f"> Gerado em {s['generated_at']} · CODE SENTINEL v{VERSION} · confiança da avaliação: **{s['confidence_label']}**",
         ""]
    if data["manual"].get("summary"):
        L += ["## Resumo executivo", "", data["manual"]["summary"], ""]
    L += ["## 1. Projeto e tecnologias", "", "| Item | Valor |", "|---|---|",
          f"| Nome do projeto | {md_cell(st.get('project') or s['project'])} |",
          f"| Linguagens (arquivos) | {md_cell(', '.join(f'{k} ({v})' for k, v in st.get('languages', {}).items()))} |",
          f"| Frameworks / bibliotecas | {md_cell(', '.join(st.get('frameworks', [])) or '-')} |",
          f"| Ferramentas de teste declaradas | {md_cell(', '.join(st.get('test_tools_declared', [])) or 'nenhuma')} |",
          f"| Linhas de código-fonte | {st.get('source_lines', '-')} |",
          f"| Arquivos de teste | {st.get('test_file_count', '-')} |",
          f"| CI configurado | {'sim' if st.get('has_ci') else 'não'} |", ""]
    L += ["## 2. Ferramentas utilizadas", "", "| Ferramenta | Versão | Status | Verificações | Observação |",
          "|---|---|---|---|---|"]
    L += [f"| {' | '.join(md_cell(x) for x in r)} |" for r in tool_rows(data)]
    L += ["", "## 3. Testes", ""]
    if t.get("executed"):
        L += [f"- **Executados** com `{t['framework']}`: {t['total']} testes — ✅ {t['passed']} passaram, "
              f"❌ {t['failed']} falharam, ⏭ {t['skipped']} ignorados."]
    else:
        L += [f"- **Testes não executados.** Motivo: {t.get('reason') or 'run_tools.py não executado'}."]
    not_run = [r for r in tool_rows(data) if r[2] != "executada"]
    if not_run:
        L += ["", "**Verificações não executadas e motivos:**", ""]
        L += [f"- `{r[0]}` ({r[2]}): {r[4] or '-'}" for r in not_run]
    L += ["", "## 4. Resumo dos problemas", "",
          f"**Total de problemas:** {s['findings_total']} (após remover duplicados entre ferramentas; {s['findings_raw_total']} brutos)",
          "", "| Gravidade | Quantidade |", "|---|---|"]
    L += [f"| {SEVERITY_PT[k]} | {v} |" for k, v in s["by_severity"].items()]
    L += ["", "| Classificação | Quantidade |", "|---|---|"]
    L += [f"| {STATUS_PT.get(k, k)} | {v} |" for k, v in s["by_status"].items()]
    L += ["", "## 5. Vulnerabilidades identificadas", ""]
    L += ([f"- [{SEVERITY_PT[f['severity']]}] {f['title']} — `{f['file']}:{f['line']}` ({STATUS_PT[f['status']]})"
           for f in sec[:40]] or ["- Nenhuma vulnerabilidade identificada **pelas verificações executadas** "
                                  "(isso não prova ausência de vulnerabilidades)."])
    L += ["", "## 6. Problemas de performance", ""]
    L += ([f"- [{SEVERITY_PT[f['severity']]}] {f['title']} — `{f['file']}:{f['line']}`" for f in perf[:20]]
          or ["- Nenhum identificado pelas heurísticas (sem teste de carga, a confiança é limitada)."])
    L += ["", "## 7. Cobertura de testes", ""]
    cov = t.get("coverage")
    L += [f"- Linhas: **{cov['lines']}%** · Branches: {cov.get('branches', '-')}% · Funções: {cov.get('functions', '-')}% "
          f"(fonte: {cov.get('source')})" if cov else "- Não mensurável nesta execução."]
    if t.get("edge_case_categories") is not None:
        L += [f"- Categorias de casos de borda presentes nos testes: {', '.join(t['edge_case_categories']) or 'nenhuma'}"]
    L += ["", "## 8. Principais pontos de risco", ""]
    L += [f"{i}. **{f['title']}** (`{f['file']}:{f['line']}`) — {f.get('failure_mode', '')}"
          for i, f in enumerate([f for f in fs if f["severity"] in ("CRITICAL", "HIGH")][:7], 1)] or \
         ["- Nenhum risco crítico/alto identificado pelas verificações executadas."]
    L += ["", "## 9. Achados detalhados", ""]
    for i, f in enumerate(fs[:80], 1):
        L += [finding_md(i, f), ""]
    if len(fs) > 80:
        L += [f"_… mais {len(fs) - 80} achados em `findings-merged.json`._", ""]
    L += ["## 10. Recomendações de correção", ""] + sum(([r, ""] for r in recommendations(fs)), [])
    L += ["---", "", f"## CODE INTEGRITY SCORE: {s['score']}/100", "",
          f"## NÍVEL DE PROTEÇÃO: {s['level_name'].upper()} (Nível {s['level']}/5)", "",
          f'<p align="center"><img src="{padlock_rel}" width="220" alt="Cadeado nível {s["level"]} — {s["level_name"]}"></p>',
          "", "| Critério | Pontos | Confiança | Verificações ausentes |", "|---|---|---|---|"]
    for c in CATEGORIES:
        k = s["criteria"][c]
        L.append(f"| {k['name']} | {k['points']}/{k['max']} | {int(k['confidence'] * 100)}% | "
                 f"{md_cell(', '.join(k.get('checks_missing', [])) or '-')} |")
    L += ["", f"Pontuação bruta: {s['raw_score']} · Confiança geral: {s['confidence_label']} ({int(s['confidence'] * 100)}%)", ""]
    if s["caps_applied"]:
        L += ["**Tetos aplicados (gates):**", ""] + [f"- máx. {c['max']}: {c['reason']}" for c in s["caps_applied"]] + [""]
    L += ["## Parecer final", "", "| Etapa | Situação | Motivos |", "|---|---|---|"]
    icon = {"APTO": "✅", "APTO COM RESSALVAS": "⚠️", "NÃO APTO": "⛔"}
    L += [f"| {r['stage']} | {icon[r['status']]} {r['status']} | {md_cell('; '.join(r['reasons']))} |" for r in s["readiness"]]
    L += ["", final_summary(s), "",
          "_Este relatório reflete apenas as verificações listadas acima. Ausência de achados não é prova de "
          "ausência de vulnerabilidades._", ""]
    return "\n".join(L)


def final_summary(s: dict) -> str:
    stages = {r["stage"]: r["status"] for r in s["readiness"]}
    best = next((st for st in ("Produção", "Homologação", "Testes (QA)", "Desenvolvimento")
                 if stages.get(st) in ("APTO", "APTO COM RESSALVAS")), "Desenvolvimento")
    return (f"**Conclusão:** o projeto atingiu **{s['score']}/100 ({s['level_name']})** e está apto, no máximo, para "
            f"**{best}**" + (" (com ressalvas)" if stages.get(best) == "APTO COM RESSALVAS" else "") +
            ". A liberação para produção depende dos critérios de segurança e estabilidade listados, não apenas da nota.")


# ------------------------------------------------------------------ HTML
CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#14171c;--muted:#5b6470;--line:#e3e6ea;--accent:#2563eb;--code:#f1f3f6}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0d1117;--card:#151b23;--fg:#e6edf3;--muted:#9aa5b1;--line:#262f3a;--accent:#60a5fa;--code:#0b0f14}}
:root[data-theme=dark]{--bg:#0d1117;--card:#151b23;--fg:#e6edf3;--muted:#9aa5b1;--line:#262f3a;--accent:#60a5fa;--code:#0b0f14}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:24px 16px 64px;overflow-wrap:anywhere}
h1{font-size:22px;letter-spacing:.06em;margin:0}h2{font-size:18px;margin:32px 0 12px}h3{font-size:15px;margin:0 0 6px}
.muted{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin:12px 0}
.hero{display:grid;grid-template-columns:220px 1fr;gap:24px;align-items:center}
.hero svg{width:100%;height:auto}.score{font-size:56px;font-weight:800;line-height:1}.score small{font-size:20px;color:var(--muted)}
.level{font-size:18px;font-weight:700;margin-top:6px}
.bars{display:grid;gap:8px;margin-top:14px}.bar{display:grid;grid-template-columns:200px 1fr 70px;gap:10px;align-items:center;font-size:13px}
.track{height:10px;background:var(--line);border-radius:6px;overflow:hidden}.fill{height:100%;border-radius:6px}
table{width:100%;border-collapse:collapse;font-size:13.5px}.tbl{overflow-x:auto}th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}.pill{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:700;color:#fff}
.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}.stat{text-align:center;padding:12px;border-radius:12px;border:1px solid var(--line);background:var(--card)}
.stat b{display:block;font-size:26px}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word}
summary code{word-break:break-all}details{min-width:0;border:1px solid var(--line);border-radius:12px;background:var(--card);margin:8px 0}summary{cursor:pointer;padding:12px 14px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
details .body{padding:0 14px 14px}dl{display:grid;grid-template-columns:190px 1fr;gap:4px 12px;margin:0 0 10px}dt{color:var(--muted)}dd{margin:0}
.ready td:nth-child(2){font-weight:700;white-space:nowrap}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
@media (max-width:720px){.hero{grid-template-columns:1fr;justify-items:center;text-align:center}.bar{grid-template-columns:1fr 60px}.bar .track{grid-column:1/-1;order:3}.grid{grid-template-columns:repeat(2,1fr)}dl{grid-template-columns:1fr}}
"""


def e(x) -> str:
    return html.escape(str(x if x is not None else "-"))


def build_html(data: dict, svg: str) -> str:
    s, st, fs = data["score"], data["stack"], data["findings"]
    t = s["tests"]
    lvl_color = {1: "#d7263d", 2: "#f39c12", 3: "#3b82f6", 4: "#10b981", 5: "#d4a106"}[s["level"]]
    bars = ""
    for c in CATEGORIES:
        k = s["criteria"][c]
        pct = 100 * k["points"] / k["max"]
        col = "#10b981" if pct >= 75 else "#3b82f6" if pct >= 60 else "#f39c12" if pct >= 40 else "#d7263d"
        bars += (f'<div class="bar"><span>{e(k["name"])} <span class="muted">· conf. {int(k["confidence"] * 100)}%</span></span>'
                 f'<div class="track"><div class="fill" style="width:{pct:.0f}%;background:{col}"></div></div>'
                 f'<b>{k["points"]}/{k["max"]}</b></div>')
    stats = "".join(f'<div class="stat"><b style="color:{SEV_COLOR[k]}">{v}</b>{SEVERITY_PT[k]}</div>'
                    for k, v in s["by_severity"].items())
    tools = "".join(f"<tr><td>{e(r[0])}</td><td><code>{e(r[1])}</code></td><td>{e(r[2])}</td><td>{e(r[3])}</td>"
                    f"<td>{e(r[4])}</td></tr>" for r in tool_rows(data))
    caps = "".join(f"<li>máx. <b>{c['max']}</b>: {e(c['reason'])}</li>" for c in s["caps_applied"])
    icon = {"APTO": "✅", "APTO COM RESSALVAS": "⚠️", "NÃO APTO": "⛔"}
    ready = "".join(f"<tr><td>{e(r['stage'])}</td><td>{icon[r['status']]} {e(r['status'])}</td>"
                    f"<td>{e('; '.join(r['reasons']))}</td></tr>" for r in s["readiness"])
    cards = ""
    for i, f in enumerate(fs[:150], 1):
        refs = " · ".join(x for x in (f.get("cwe"), f.get("owasp")) if x)
        cards += (f'<details{" open" if f["severity"] == "CRITICAL" and i <= 3 else ""}><summary>'
                  f'<span class="pill" style="background:{SEV_COLOR[f["severity"]]}">{SEVERITY_PT[f["severity"]]}</span>'
                  f'<b>{e(f["title"])}</b><code class="muted">{e(f.get("file"))}:{e(f.get("line"))}</code>'
                  f'<span class="muted">· {e(STATUS_PT.get(f["status"], f["status"]))}</span></summary><div class="body"><dl>'
                  f'<dt>O que está acontecendo</dt><dd>{e(f.get("description"))}</dd>'
                  f'<dt>Como pode quebrar</dt><dd>{e(f.get("failure_mode"))}</dd>'
                  f'<dt>Impacto potencial</dt><dd>{e(f.get("impact") or f.get("failure_mode"))}</dd>'
                  f'<dt>Probabilidade</dt><dd>{e(f.get("likelihood"))}</dd>'
                  f'<dt>Categoria</dt><dd>{e(CATEGORY_PT.get(f["category"]))}</dd>'
                  f'<dt>Origem</dt><dd>{e(", ".join([f.get("source", "")] + f.get("also_reported_by", [])))}</dd>'
                  + (f'<dt>Referência</dt><dd>{e(refs)}</dd>' if refs else "") +
                  f'<dt>Correção sugerida</dt><dd>{e(f.get("fix"))}</dd></dl>'
                  + (f'<div class="muted">Evidência</div><pre>{e(f["evidence"])}</pre>' if f.get("evidence") else "")
                  + (f'<div class="muted">Código corrigido / exemplo</div><pre>{e(f["fixed_code"])}</pre>'
                     if f.get("fixed_code") else "") + "</div></details>")
    summary = f'<div class="card"><h3>Resumo executivo</h3><p>{e(data["manual"]["summary"])}</p></div>' \
        if data["manual"].get("summary") else ""
    tests_txt = (f"{t['total']} testes com <code>{e(t['framework'])}</code>: {t['passed']} passaram, "
                 f"<b>{t['failed']} falharam</b>, {t['skipped']} ignorados." if t.get("executed")
                 else f"Testes não executados — {e(t.get('reason'))}.")
    cov = t.get("coverage")
    cov_txt = (f"Linhas {cov['lines']}% · branches {cov.get('branches', '-')}% · funções {cov.get('functions', '-')}%"
               if cov else "Não mensurável nesta execução.")
    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Code Sentinel Report</title>
<style>{CSS}</style></head><body><div class="wrap">
<p class="muted" style="margin:0 0 4px">CODE SENTINEL v{VERSION} · {e(s['generated_at'])}</p>
<h1>CODE SENTINEL — RELATÓRIO DE INTEGRIDADE</h1>
<p class="muted">Projeto <b>{e(st.get('project') or s['project'])}</b> · {e(', '.join(st.get('languages', {}).keys()))}
{(' · ' + e(', '.join(st.get('frameworks', [])))) if st.get('frameworks') else ''}</p>
<div class="card hero"><div>{svg}</div><div>
<div class="muted">CODE INTEGRITY SCORE</div><div class="score">{s['score']}<small>/100</small></div>
<div class="level" style="color:{lvl_color}">NÍVEL DE PROTEÇÃO: {e(s['level_name'].upper())} · {s['level']}/5</div>
<div class="muted">Confiança da avaliação: <b>{e(s['confidence_label'])}</b> ({int(s['confidence'] * 100)}%) · bruto {s['raw_score']}</div>
<div class="bars">{bars}</div></div></div>
{('<div class="card"><h3>Tetos aplicados</h3><ul>' + caps + '</ul></div>') if caps else ''}
{summary}
<h2>Parecer</h2><div class="card tbl"><table class="ready"><tr><th>Etapa</th><th>Situação</th><th>Motivos</th></tr>{ready}</table>
<p>{e(final_summary(s)).replace('**', '')}</p></div>
<h2>Problemas por gravidade</h2><div class="grid">{stats}</div>
<p class="muted">{s['findings_total']} achados únicos ({s['findings_raw_total']} brutos) ·
confirmados {s['by_status'].get('confirmed', 0)} · riscos potenciais {s['by_status'].get('potential', 0)} ·
hipóteses {s['by_status'].get('hypothesis', 0)}</p>
<h2>Testes e cobertura</h2><div class="card"><p>{tests_txt}</p><p>Cobertura: {cov_txt}</p>
<p class="muted">Casos de borda nos testes: {e(', '.join(t.get('edge_case_categories') or []) or 'nenhum identificado')}</p></div>
<h2>Ferramentas</h2><div class="card" style="overflow:auto"><table><tr><th>Ferramenta</th><th>Versão</th><th>Status</th>
<th>Verificações</th><th>Observação</th></tr>{tools}</table></div>
<h2>Achados</h2>{cards or '<p class="muted">Nenhum achado nas verificações executadas.</p>'}
<p class="muted" style="margin-top:32px">Este relatório reflete apenas as verificações listadas. Ausência de achados não
prova ausência de vulnerabilidades.</p>
</div></body></html>"""


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--out")
    ap.add_argument("--format", default="md,html")
    a = ap.parse_args()
    d = out_dir(Path(a.project), a.out)
    data = load(d)
    if not data["score"]:
        sys.exit("score.json ausente: rode scripts/cis_score.py antes.")
    lvl = data["score"]["level"]
    fmts = set(a.format.split(","))
    if "md" in fmts:
        png = PADLOCKS / f"level-{lvl}.png"
        img = f"padlock-level-{lvl}.png"
        if png.exists():
            shutil.copyfile(png, d / img)
        else:
            img = f"padlock-level-{lvl}.svg"
            shutil.copyfile(PADLOCKS / f"level-{lvl}.svg", d / img)
        (d / "report.md").write_text(build_md(data, img), encoding="utf-8")
        print(f"[report] {d / 'report.md'}")
    if "html" in fmts:
        svg = (PADLOCKS / f"level-{lvl}.svg").read_text(encoding="utf-8")
        svg = svg.split("?>", 1)[-1]
        # ids únicos por documento não são necessários: um único cadeado por relatório
        (d / "report.html").write_text(build_html(data, svg), encoding="utf-8")
        print(f"[report] {d / 'report.html'}")


if __name__ == "__main__":
    main()
