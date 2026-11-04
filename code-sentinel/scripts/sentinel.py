#!/usr/bin/env python3
"""CODE SENTINEL — orquestrador da auditoria.

Comandos:
  audit    <projeto> [--run-tests] [--out DIR] [--skip grupos] [--timeout S]
           Executa: detect_stack -> scan_secrets -> scan_patterns -> run_tools -> cis_score -> render_report
  rescore  <projeto> [--out DIR]
           Recalcula nota e relatório (ex.: após adicionar findings/manual.json e evidence/manual.json)
  snapshot <projeto> <rotulo> [--out DIR]
           Guarda score + achados atuais em <out>/history/<rotulo>/ (use "antes" no modo de correção)
  compare  <projeto> <rotulo_antes> [<rotulo_depois>] [--out DIR]
           Compara dois snapshots (ou snapshot vs. estado atual) e grava comparison.md

Nada aqui instala pacotes, altera o código do projeto ou executa comandos destrutivos.
Tudo é gravado em <projeto>/.code-sentinel/ (que recebe um .gitignore próprio).
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import SEVERITIES, SEVERITY_PT, load_json, out_dir  # noqa: E402


def step(script: str, *args: str) -> None:
    cp = subprocess.run([sys.executable, str(HERE / script), *args])
    if cp.returncode != 0:
        print(f"[sentinel] AVISO: {script} terminou com código {cp.returncode} (seguindo; isso fica registrado)")


def audit(a) -> None:
    common = [a.project] + (["--out", a.out] if a.out else [])
    step("detect_stack.py", *common)
    step("scan_secrets.py", *common)
    step("scan_patterns.py", *common)
    extra = (["--run-tests"] if a.run_tests else []) + (["--skip", a.skip] if a.skip else []) + \
            ["--timeout", str(a.timeout)]
    step("run_tools.py", *common, *extra)
    rescore(a)


def rescore(a) -> None:
    common = [a.project] + (["--out", a.out] if a.out else [])
    step("cis_score.py", *common)
    step("render_report.py", *common)
    d = out_dir(Path(a.project), a.out)
    s = load_json(d / "score.json", {})
    if s:
        print("\n" + "=" * 64)
        print(f" CODE INTEGRITY SCORE: {s['score']}/100   NÍVEL {s['level']}: {s['level_name'].upper()}")
        print(f" Achados: " + ", ".join(f"{SEVERITY_PT[k]} {v}" for k, v in s["by_severity"].items()))
        for r in s["readiness"]:
            print(f"  - {r['stage']}: {r['status']}")
        print(f" Relatórios: {d / 'report.md'} | {d / 'report.html'}")
        print("=" * 64)


def snapshot(a) -> None:
    d = out_dir(Path(a.project), a.out)
    dst = d / "history" / a.label
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    for f in ("score.json", "findings-merged.json", "report.md"):
        if (d / f).exists():
            shutil.copy2(d / f, dst / f)
    print(f"[sentinel] snapshot '{a.label}' -> {dst}")


def _key(f: dict) -> tuple:
    return (f.get("rule_id"), f.get("file"), f.get("title") if str(f.get("rule_id", "")).startswith(("npm", "TEST")) else None)


def compare(a) -> None:
    d = out_dir(Path(a.project), a.out)
    b = d / "history" / a.before
    after = d / "history" / a.after if a.after else d
    sb, sa = load_json(b / "score.json"), load_json(after / "score.json")
    if not sb or not sa:
        sys.exit("snapshots/score ausentes")
    fb = (load_json(b / "findings-merged.json", {}) or {}).get("findings", [])
    fa = (load_json(after / "findings-merged.json", {}) or {}).get("findings", [])
    kb, ka = {_key(f): f for f in fb}, {_key(f): f for f in fa}
    fixed = [kb[k] for k in kb if k not in ka]
    new = [ka[k] for k in ka if k not in kb]
    L = ["# CODE SENTINEL — Comparação antes × depois", "",
         f"| Métrica | Antes ({a.before}) | Depois ({a.after or 'atual'}) | Δ |", "|---|---|---|---|",
         f"| CODE INTEGRITY SCORE | {sb['score']} | {sa['score']} | {sa['score'] - sb['score']:+d} |",
         f"| Nível | {sb['level']} — {sb['level_name']} | {sa['level']} — {sa['level_name']} | {sa['level'] - sb['level']:+d} |",
         f"| Total de achados | {sb['findings_total']} | {sa['findings_total']} | {sa['findings_total'] - sb['findings_total']:+d} |"]
    for s in SEVERITIES:
        x, y = sb["by_severity"].get(s, 0), sa["by_severity"].get(s, 0)
        L.append(f"| {SEVERITY_PT[s]} | {x} | {y} | {y - x:+d} |")
    tb, ta = sb.get("tests") or {}, sa.get("tests") or {}
    L.append(f"| Testes (passaram/total) | {tb.get('passed')}/{tb.get('total')} | {ta.get('passed')}/{ta.get('total')} | |")
    L += ["", f"## Resolvidos ({len(fixed)})", ""] + [f"- [{SEVERITY_PT[f['severity']]}] {f['title']} — `{f.get('file')}:{f.get('line')}`" for f in fixed]
    L += ["", f"## Novos / regressões ({len(new)})", ""] + \
         ([f"- [{SEVERITY_PT[f['severity']]}] {f['title']} — `{f.get('file')}:{f.get('line')}`" for f in new] or ["- nenhum"])
    out = d / "comparison.md"
    out.write_text("\n".join(L) + "\n", encoding="utf-8")
    print("\n".join(L[:12]))
    print(f"[sentinel] -> {out}")
    if new:
        print(f"[sentinel] ATENÇÃO: {len(new)} achado(s) novo(s) após a correção — verificar regressões.")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("audit")
    p.add_argument("project")
    p.add_argument("--out")
    p.add_argument("--run-tests", action="store_true")
    p.add_argument("--skip", default="")
    p.add_argument("--timeout", type=int, default=600)
    p.set_defaults(fn=audit)
    p = sub.add_parser("rescore")
    p.add_argument("project")
    p.add_argument("--out")
    p.set_defaults(fn=rescore)
    p = sub.add_parser("snapshot")
    p.add_argument("project")
    p.add_argument("label")
    p.add_argument("--out")
    p.set_defaults(fn=snapshot)
    p = sub.add_parser("compare")
    p.add_argument("project")
    p.add_argument("before")
    p.add_argument("after", nargs="?")
    p.add_argument("--out")
    p.set_defaults(fn=compare)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
