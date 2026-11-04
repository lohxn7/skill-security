#!/usr/bin/env python3
"""Calcula o CODE INTEGRITY SCORE (CIS, 0-100), o nível do cadeado e a prontidão.

Uso:
    python3 scripts/cis_score.py <projeto> [--out DIR]

Lê <out>/findings/*.json e <out>/evidence/*.json e grava <out>/score.json.
A metodologia completa (e o porquê de cada regra) está em references/scoring.md.

Resumo:
  pontos(critério) = peso × confiança × saúde
    confiança = fração (ponderada) das verificações do critério que FORAM EXECUTADAS
                -> sem verificação não há ponto: "não encontrei erro" não vale nota
    saúde     = 1 − Σ penalidades dos achados (gravidade × status), com retorno
                decrescente para repetições da mesma regra
  Testes (20) têm fórmula própria: taxa de aprovação, cobertura medida e casos de borda.
  Tetos (gates) são aplicados DEPOIS da soma: críticos, falhas de teste, ausência de
  testes ou de verificação de segurança limitam o nível, mesmo com média alta.
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (CATEGORIES, CATEGORY_PT, RESOLVED_STATUSES, SEVERITIES, load_all, load_json, now_iso, out_dir,  # noqa: E402
                    write_json)

MAX = {"tests": 20, "security": 25, "integrity": 20, "stability": 15, "performance": 10, "maintainability": 10}
CHECKS = {
    "security": {"deps": 0.25, "secrets": 0.15, "sast": 0.20, "sast_heuristic": 0.15, "manual_security_review": 0.25},
    "integrity": {"syntax": 0.20, "types": 0.15, "lint": 0.15, "tests_executed": 0.25, "manual_logic_review": 0.25},
    "stability": {"error_handling_heuristic": 0.25, "edge_case_tests": 0.35, "tests_executed": 0.15,
                  "manual_error_review": 0.25},
    "performance": {"perf_heuristic": 0.35, "perf_tests": 0.30, "manual_perf_review": 0.35},
    "maintainability": {"lint": 0.30, "duplication": 0.25, "complexity_heuristic": 0.20, "format": 0.05,
                        "manual_arch_review": 0.20},
}
CHECK_PT = {
    "deps": "auditoria de dependências", "secrets": "varredura de segredos", "sast": "SAST dedicado (Semgrep/CodeQL/bandit)",
    "sast_heuristic": "SAST heurístico (scan_patterns)", "manual_security_review": "revisão manual de segurança",
    "syntax": "verificação de sintaxe", "types": "checagem de tipos", "lint": "lint", "tests_executed": "testes executados",
    "manual_logic_review": "revisão manual de lógica", "error_handling_heuristic": "heurística de tratamento de erros",
    "edge_case_tests": "testes de borda/estresse", "manual_error_review": "revisão manual de erros",
    "perf_heuristic": "heurística de performance", "perf_tests": "testes de carga/benchmark",
    "manual_perf_review": "revisão manual de performance", "duplication": "detecção de duplicação",
    "complexity_heuristic": "heurística de complexidade", "format": "formatação", "manual_arch_review": "revisão de arquitetura",
    "coverage": "cobertura medida",
}
SEV_PENALTY = {"CRITICAL": 0.60, "HIGH": 0.30, "MEDIUM": 0.12, "LOW": 0.04, "INFO": 0.0}
STATUS_FACTOR = {"confirmed": 1.0, "potential": 0.5, "hypothesis": 0.2}
LEVELS = [
    (90, 5, "Integridade Máxima"), (75, 4, "Alta Integridade"), (60, 3, "Proteção Moderada"),
    (40, 2, "Proteção Fraca"), (0, 1, "Código Exposto"),
]


def _matches(t: dict, f: dict) -> bool:
    if f is t or str(f.get("file")) != str(t.get("file")) or int(f.get("line") or 0) != int(t.get("line") or 0):
        return False
    target = t.get("target_rule_id")
    return f.get("rule_id") == target if target else f.get("category") == t.get("category")


def apply_triage(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    """Aplica a triagem manual: entradas com status false_positive/fixed/accepted_risk removem os achados
    correspondentes; entradas com "override": true substituem os achados correspondentes (rebaixar/elevar)."""
    triage = [f for f in findings if f.get("status") in RESOLVED_STATUSES or f.get("override")]
    resolved = []
    keep = []
    for f in findings:
        if f in triage:
            continue
        hit = next((t for t in triage if _matches(t, f)), None)
        if hit is None:
            keep.append(f)
        elif hit.get("status") in RESOLVED_STATUSES:
            resolved.append({**f, "triage": hit.get("status"), "justification": hit.get("justification", "")})
    keep += [t for t in triage if t.get("status") not in RESOLVED_STATUSES]
    return keep, resolved


def dedupe(findings: list[dict]) -> list[dict]:
    """Une achados do mesmo local/categoria vindos de fontes diferentes (ex.: Semgrep + heurística)."""
    by_key: dict[tuple, dict] = {}
    rank_s = {s: i for i, s in enumerate(SEVERITIES)}
    rank_st = {"confirmed": 0, "potential": 1, "hypothesis": 2}
    out = []
    findings = sorted(findings, key=lambda f: (rank_s.get(f.get("severity"), 9), rank_st.get(f.get("status"), 1)))
    for f in findings:
        if f.get("status") in ("fixed", "false_positive", "accepted_risk"):
            continue
        if not f.get("file") or not f.get("line") or f.get("rule_id", "").startswith(("npm-audit", "pip-audit", "TEST-")):
            out.append(f)
            continue
        key = (f["file"], int(f["line"]), f.get("category"))
        if key in by_key:
            g = by_key[key]
            g.setdefault("also_reported_by", []).append(f.get("source"))
            if rank_s[f["severity"]] < rank_s[g["severity"]]:
                g["severity"] = f["severity"]
            if rank_st.get(f["status"], 1) < rank_st.get(g["status"], 1):
                g["status"] = f["status"]
            continue
        by_key[key] = dict(f)
        out.append(by_key[key])
    return out


def executed_checks(evidence: list[dict]) -> tuple[set, set, dict]:
    done, intended_na, tests = set(), set(), {}
    for e in evidence:
        if e.get("name") == "tests":
            tests = e
            continue
        done.update(e.get("checks", []))
        for t in e.get("tools", []):
            done.update(t.get("checks", []))
            if t.get("status") == "not_applicable":
                intended_na.update(t.get("intended_checks", []))
        intended_na.update(e.get("not_applicable", []))
    na = intended_na - done
    return done, na, tests


def penalty(fs: list[dict]) -> tuple[float, list[dict]]:
    groups = defaultdict(list)
    for f in fs:
        groups[f.get("rule_id") or f.get("title")].append(f)
    total, detail = 0.0, []
    for rid, items in groups.items():
        items.sort(key=lambda f: -SEV_PENALTY[f["severity"]] * STATUS_FACTOR.get(f["status"], 0.5))
        p = sum(SEV_PENALTY[f["severity"]] * STATUS_FACTOR.get(f["status"], 0.5) * (0.5 ** i)
                for i, f in enumerate(items[:6]))
        if p:
            detail.append({"rule": rid, "count": len(items), "penalty": round(p, 3)})
        total += p
    detail.sort(key=lambda d: -d["penalty"])
    return total, detail


def score(d: Path) -> dict:
    raw_findings, evidence = load_all(d)
    triaged, resolved = apply_triage(raw_findings)
    findings = dedupe(triaged)
    done, na, tests = executed_checks(evidence)
    stack = load_json(d / "stack.json", {}) or {}
    if not stack.get("is_typescript"):
        na.add("types")  # JS puro/Python sem mypy: checagem de tipos não se aplica
    if tests.get("executed") and len(tests.get("edge_case_categories", [])) >= 3:
        done.add("edge_case_tests")
    if tests.get("executed"):
        done.add("tests_executed")
    if tests.get("coverage"):
        done.add("coverage")
    by_cat = defaultdict(list)
    for f in findings:
        by_cat[f.get("category", "integrity")].append(f)

    criteria = {}
    for cat in CATEGORIES:
        if cat == "tests":
            criteria[cat] = tests_criterion(tests, by_cat["tests"])
            continue
        weights = {k: w for k, w in CHECKS[cat].items() if k not in na}
        tw = sum(weights.values()) or 1
        conf = sum(w for k, w in weights.items() if k in done) / tw
        pen, detail = penalty(by_cat[cat])
        health = max(0.0, 1 - pen)
        pts = MAX[cat] * conf * health
        criteria[cat] = {
            "name": CATEGORY_PT[cat], "max": MAX[cat], "points": round(pts, 1), "confidence": round(conf, 2),
            "health": round(health, 2), "findings": len(by_cat[cat]),
            "checks_done": [CHECK_PT.get(k, k) for k in weights if k in done],
            "checks_missing": [CHECK_PT.get(k, k) for k in weights if k not in done],
            "penalties": detail[:8],
        }

    sev = Counter(f["severity"] for f in findings)
    open_ = lambda s, st=None, cat=None: [f for f in findings if f["severity"] == s  # noqa: E731
                                          and (st is None or f["status"] == st) and (cat is None or f["category"] == cat)]
    caps = []
    crit_conf = open_("CRITICAL", "confirmed")
    if crit_conf:
        caps.append((59, f"{len(crit_conf)} problema(s) CRÍTICO(s) confirmado(s)"))
        if any(f["category"] == "security" for f in crit_conf):
            criteria["security"]["points"] = min(criteria["security"]["points"], 5.0)
            criteria["security"]["capped"] = "vulnerabilidade crítica confirmada: segurança limitada a 5/25"
    if open_("CRITICAL", "potential") or open_("CRITICAL", "hypothesis"):
        caps.append((74, "risco CRÍTICO potencial ainda não descartado"))
    if open_("HIGH", "confirmed", "security"):
        caps.append((74, "vulnerabilidade ALTA confirmada"))
    if open_("HIGH", "potential", "security") or open_("HIGH", "confirmed"):
        caps.append((89, "achado(s) de gravidade ALTA em aberto"))
    if not tests.get("executed"):
        caps.append((74, "testes automatizados não executados/inexistentes: confiabilidade não comprovada"))
    else:
        if tests.get("failed", 0) > 0:
            caps.append((74, f"{tests['failed']} teste(s) falhando"))
        cov = (tests.get("coverage") or {}).get("lines")
        if cov is None:
            caps.append((89, "cobertura de testes não medida"))
        elif cov < 60:
            caps.append((74, f"cobertura de linhas {cov:.0f}% (< 60%)"))
        elif cov < 80:
            caps.append((89, f"cobertura de linhas {cov:.0f}% (< 80%)"))
    if criteria["security"]["confidence"] < 0.5:
        caps.append((74, "verificações de segurança insuficientes (confiança < 50%): não é possível afirmar segurança"))
    elif not {"deps", "secrets"} <= (done | na) or ("sast" not in done and "manual_security_review" not in done):
        caps.append((89, "nível máximo exige auditoria de dependências, segredos e SAST/revisão de segurança"))

    if "lint" not in done and "lint" not in na:
        caps.append((89, "nível máximo exige lint/análise estática de qualidade executada (ESLint, ruff...)"))

    raw_total = round(sum(c["points"] for c in criteria.values()), 1)
    cap = min([c for c, _ in caps], default=100)
    total = int(round(min(raw_total, cap)))
    level_num, level_name = next((n, name) for thr, n, name in LEVELS if total >= thr)
    conf_vals = [criteria[c]["confidence"] * MAX[c] for c in CATEGORIES]
    overall_conf = sum(conf_vals) / 100
    conf_label = "Alta" if overall_conf >= 0.75 else "Média" if overall_conf >= 0.45 else "Baixa"

    result = {
        "generated_at": now_iso(),
        "project": stack.get("project") or d.parent.name,
        "score": total, "raw_score": raw_total,
        "level": level_num, "level_name": level_name,
        "caps_applied": [{"max": c, "reason": r} for c, r in sorted(caps)],
        "binding_cap": next((r for c, r in sorted(caps) if c == cap and raw_total > cap), None),
        "confidence": round(overall_conf, 2), "confidence_label": conf_label,
        "criteria": criteria,
        "findings_total": len(findings),
        "findings_raw_total": len(raw_findings),
        "findings_resolved_by_triage": [{k: f.get(k) for k in ("title", "file", "line", "triage", "justification")}
                                        for f in resolved],
        "by_severity": {s: sev.get(s, 0) for s in SEVERITIES},
        "by_status": dict(Counter(f["status"] for f in findings)),
        "checks_executed": sorted(done), "checks_not_applicable": sorted(na),
        "tests": {k: tests.get(k) for k in ("executed", "framework", "total", "passed", "failed", "skipped",
                                            "coverage", "test_files", "edge_case_categories", "reason")},
        "readiness": readiness(total, findings, tests, done, na),
    }
    write_json(d / "findings-merged.json", {"findings": sort_findings(findings)})
    return result


def tests_criterion(t: dict, fs: list[dict]) -> dict:
    base = {"name": CATEGORY_PT["tests"], "max": 20}
    files = t.get("test_files", 0) or 0
    if not t:
        return {**base, "points": 0.0, "confidence": 0.0, "health": 0.0, "findings": len(fs),
                "note": "suíte de testes não avaliada (run_tools.py não executado)",
                "checks_done": [], "checks_missing": ["testes executados", "cobertura medida"]}
    if files == 0:
        return {**base, "points": 0.0, "confidence": 1.0, "health": 0.0, "findings": len(fs),
                "note": "nenhum teste automatizado no projeto", "checks_done": [], "checks_missing": ["testes"]}
    if not t.get("executed"):
        return {**base, "points": 3.0, "confidence": 0.2, "health": None, "findings": len(fs),
                "note": f"{files} arquivo(s) de teste existem, mas não foram executados: {t.get('reason')}",
                "checks_done": [], "checks_missing": ["testes executados", "cobertura medida"]}
    total = max(1, t.get("total", 0))
    pass_rate = t.get("passed", 0) / total
    cov = (t.get("coverage") or {}).get("lines")
    cov_pts = 10 * min(1.0, cov / 80) if cov is not None else 2.0
    edge = len(t.get("edge_case_categories", []))
    edge_pts = 2.0 if edge >= 3 else 1.0 if edge >= 1 else 0.0
    pts = 8 * pass_rate + cov_pts + edge_pts
    other = [f for f in fs if f.get("scored_via") != "pass_rate"]
    pen, detail = penalty(other)
    pts *= max(0.0, 1 - pen)
    return {**base, "points": round(pts, 1), "confidence": 1.0 if cov is not None else 0.7,
            "health": round(pass_rate, 2), "findings": len(fs),
            "note": f"{t.get('passed')}/{t.get('total')} testes passaram; cobertura de linhas: "
                    f"{'%.1f%%' % cov if cov is not None else 'não medida'}; categorias de casos de borda: {edge}",
            "checks_done": ["testes executados"] + (["cobertura medida"] if cov is not None else []),
            "checks_missing": [] if cov is not None else ["cobertura medida"], "penalties": detail[:5]}


def readiness(score: int, fs: list[dict], t: dict, done: set, na: set) -> list[dict]:
    crit = [f for f in fs if f["severity"] == "CRITICAL"]
    crit_c = [f for f in crit if f["status"] == "confirmed"]
    high_sec = [f for f in fs if f["severity"] == "HIGH" and f["category"] == "security"]
    high_c = [f for f in fs if f["severity"] == "HIGH" and f["status"] == "confirmed"]
    syntax = [f for f in fs if f.get("rule_id") == "SYNTAX-ERROR" or str(f.get("rule_id", "")).startswith("TS")]
    executed = t.get("executed")
    failed = t.get("failed", 0) if executed else None
    cov = (t.get("coverage") or {}).get("lines") if executed else None
    out = []

    def add(stage, ok, reasons, partial=False):
        out.append({"stage": stage, "status": "APTO" if ok and not partial else "APTO COM RESSALVAS" if ok else "NÃO APTO",
                    "reasons": reasons})

    add("Desenvolvimento", True, ["sempre apto para continuar o desenvolvimento"] +
        ([f"{len(syntax)} erro(s) de compilação/tipo bloqueiam partes do código"] if syntax else []), partial=bool(syntax))
    r = []
    if syntax:
        r.append("há erros de sintaxe/compilação")
    add("Testes (QA)", not syntax, r or ["código compila; pode ser exercitado por QA"])
    r = []
    if crit_c:
        r.append(f"{len(crit_c)} problema(s) CRÍTICO(s) confirmado(s)")
    if not executed:
        r.append("testes automatizados não executados")
    elif failed:
        r.append(f"{failed} teste(s) falhando")
    if score < 60:
        r.append(f"CIS {score} < 60")
    partial = bool([f for f in crit if f["status"] != "confirmed"])
    add("Homologação", not r, r or (["sem bloqueios críticos; riscos potenciais críticos ainda precisam ser descartados"]
                                    if partial else ["sem bloqueios críticos e suíte de testes verde"]), partial=partial)
    r = []
    if crit:
        r.append(f"{len(crit)} achado(s) CRÍTICO(s) em aberto (confirmados ou potenciais)")
    if high_sec:
        r.append(f"{len(high_sec)} achado(s) de segurança ALTO(s) em aberto")
    if high_c:
        r.append(f"{len(high_c)} achado(s) ALTO(s) confirmados")
    if not executed:
        r.append("sem evidência de testes executados")
    elif failed:
        r.append("suíte de testes não está verde")
    if cov is None:
        r.append("cobertura de testes não medida")
    elif cov < 70:
        r.append(f"cobertura {cov:.0f}% < 70%")
    if "deps" not in done and "deps" not in na:
        r.append("dependências não auditadas")
    if "secrets" not in done:
        r.append("varredura de segredos não executada")
    if "sast" not in done and "manual_security_review" not in done:
        r.append("sem SAST dedicado nem revisão manual de segurança")
    if score < 75:
        r.append(f"CIS {score} < 75")
    add("Produção", not r, r or ["critérios de segurança e estabilidade atendidos com as verificações executadas"])
    return out


def sort_findings(fs: list[dict]) -> list[dict]:
    rs = {s: i for i, s in enumerate(SEVERITIES)}
    st = {"confirmed": 0, "potential": 1, "hypothesis": 2}
    return sorted(fs, key=lambda f: (rs[f["severity"]], st.get(f["status"], 1), f.get("file", ""), f.get("line", 0)))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--out")
    a = ap.parse_args()
    d = out_dir(Path(a.project), a.out)
    res = score(d)
    write_json(d / "score.json", res)
    print(f"[score] CIS {res['score']}/100 (bruto {res['raw_score']}) - Nível {res['level']}: {res['level_name']} "
          f"| confiança {res['confidence_label']}")
    for c in res["caps_applied"]:
        print(f"[score]   teto {c['max']}: {c['reason']}")


if __name__ == "__main__":
    main()
