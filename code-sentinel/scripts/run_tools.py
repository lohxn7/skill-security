#!/usr/bin/env python3
"""Executa as ferramentas de verificação adequadas a stack e normaliza os resultados.

Uso:
    python3 scripts/run_tools.py <projeto> [--out DIR] [--run-tests] [--only syntax,deps,...]
                                 [--skip semgrep,...] [--timeout 600]

Principios:
  * NUNCA instala nada (sem `npm install`, sem `npx` que baixe pacotes). Ferramenta ausente
    e registrada como "not_installed" com o motivo -- isso reduz a confianca da nota.
  * Testes do projeto so rodam com --run-tests (executam código do projeto; confirme com o
    usuário que não apontam para produção/servicos reais).
  * Toda ferramenta tem timeout; saidas brutas ficam em <out>/raw/.
  * Nada e escondido: falhas de ferramenta e testes falhando viram evidência/achados.

Grupos (--only/--skip): syntax, types, lint, format, deps, sast, python, tests
Saída: <out>/evidence/tools.json, <out>/evidence/tests.json, <out>/findings/<ferramenta>.json
"""
from __future__ import annotations

import argparse
import ast
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (finalize_findings, is_test_file, is_test_path, iter_files, load_json, now_iso, out_dir, read_text,  # noqa: E402
                    rel, run, save_evidence, save_findings, tool_version, which, write_json)

ESLINT_CONFIGS = [".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json", ".eslintrc.yml", ".eslintrc.yaml",
                  "eslint.config.js", "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts"]


class Ctx:
    def __init__(self, project: Path, out: Path, timeout: int):
        self.project, self.out, self.timeout = project, out, timeout
        self.tools: list[dict] = []
        pkg = load_json(project / "package.json", {}) or {}
        self.pkg = pkg
        self.js_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}

    def record(self, name, status, checks, *, version=None, reason=None, cmd=None, res=None, findings=None,
               extra=None):
        e = {"tool": name, "status": status, "checks": checks if status == "executed" else [],
             "intended_checks": checks, "version": version, "reason": reason,
             "command": " ".join(cmd) if cmd else None}
        if res:
            e.update(exit_code=res["exit_code"], duration_s=res["duration_s"], timed_out=res["timed_out"])
        if findings is not None:
            e["findings"] = len(findings)
            save_findings(self.out, name, finalize_findings(findings, name.upper().replace("-", "")[:6]))
        if extra:
            e.update(extra)
        self.tools.append(e)
        tag = {"executed": "ok", "failed": "FALHOU", "not_installed": "ausente",
               "skipped": "pulado", "not_applicable": "n/a"}.get(status, status)
        print(f"[tools] {name:<12} {tag:<8} {reason or ''}".rstrip())

    def raw(self, name: str, content: str) -> str:
        p = self.out / "raw" / name
        p.write_text(content or "", encoding="utf-8")
        return str(p)


# ------------------------------------------------------------------ sintaxe
def syntax(c: Ctx) -> None:
    js_files, py_files = [], []
    for p in iter_files(c.project):
        if p.suffix in (".js", ".cjs", ".mjs"):
            js_files.append(p)
        elif p.suffix == ".py":
            py_files.append(p)
    findings = []
    if py_files:
        for p in py_files:
            src = read_text(p)
            if src is None:
                continue
            try:
                ast.parse(src, filename=str(p))  # apenas parse; nada e executado
            except SyntaxError as ex:
                findings.append(_syntax_finding(rel(c.project, p), ex.lineno or 1, str(ex.msg), "python"))
        c.record("py-syntax", "executed", ["syntax"], version=f"python {sys.version.split()[0]} (ast.parse)",
                 findings=findings, extra={"files": len(py_files)})
    else:
        c.record("py-syntax", "not_applicable", ["syntax"], reason="sem arquivos .py")
    findings = []
    node = which("node")
    if js_files and node:
        ver = tool_version([node, "--version"], c.project)
        for p in js_files[:600]:
            r = run([node, "--check", str(p)], c.project, timeout=30)
            if r["exit_code"] not in (0, None):
                err = r["stderr"]
                m = re.search(r":(\d+)\s*\n", err)
                msg = next((l for l in err.splitlines() if "Error" in l), err.strip()[:200])
                findings.append(_syntax_finding(rel(c.project, p), int(m.group(1)) if m else 1, msg, "node"))
        c.record("node-syntax", "executed", ["syntax"], version=f"node {ver}", findings=findings,
                 extra={"files": min(len(js_files), 600), "truncated": len(js_files) > 600})
    elif js_files:
        c.record("node-syntax", "not_installed", ["syntax"], reason="node não encontrado no PATH")
    else:
        c.record("node-syntax", "not_applicable", ["syntax"], reason="sem arquivos .js/.cjs/.mjs")


def _syntax_finding(f, line, msg, src):
    return {"rule_id": "SYNTAX-ERROR", "title": "Erro de sintaxe (arquivo não compila)", "severity": "CRITICAL",
            "status": "confirmed", "category": "integrity", "file": f, "line": line,
            "description": msg.strip(), "failure_mode": "O modulo falha ao ser carregado; tudo que o importa quebra "
                                                       "em tempo de execução ou de build.",
            "likelihood": "certa", "impact": "Indisponibilidade da funcionalidade/aplicação.",
            "fix": "Corrigir a sintaxe e adicionar verificação (lint/tsc/build) no CI.", "source": f"{src}-syntax",
            "evidence": msg.strip()[:240]}


# ------------------------------------------------------------------ tipos
def types(c: Ctx) -> None:
    tsconfig = c.project / "tsconfig.json"
    if not tsconfig.exists():
        c.record("tsc", "not_applicable", ["types"], reason="sem tsconfig.json")
        return
    tsc = which("tsc", c.project)
    if not tsc:
        c.record("tsc", "not_installed", ["types"], reason="typescript não instalado (node_modules/.bin/tsc ausente)")
        return
    cmd = [tsc, "--noEmit", "-p", str(tsconfig), "--pretty", "false"]
    r = run(cmd, c.project, c.timeout)
    c.raw("tsc.txt", r["stdout"] + r["stderr"])
    findings = []
    for m in re.finditer(r"^(.+?)\((\d+),(\d+)\): error (TS\d+): (.+)$", r["stdout"], re.M):
        findings.append({"rule_id": m.group(4), "title": f"Erro de tipo {m.group(4)}", "severity": "HIGH",
                         "status": "confirmed", "category": "integrity", "file": m.group(1), "line": int(m.group(2)),
                         "description": m.group(5), "failure_mode": "Contrato de tipos violado: valor pode ser "
                         "undefined/incompatível em tempo de execução.", "likelihood": "alta",
                         "fix": "Corrigir o tipo ou tratar o caso ausente explicitamente.", "source": "tsc",
                         "evidence": m.group(0)[:240]})
    status = "executed" if r["exit_code"] in (0, 1, 2) and not r["timed_out"] else "failed"
    c.record("tsc", status, ["types"], version=tool_version([tsc, "--version"], c.project), cmd=cmd, res=r,
             findings=findings, reason=None if status == "executed" else (r["stderr"] or "timeout")[:200])


# ------------------------------------------------------------------ lint
def lint(c: Ctx) -> None:
    has_js = any(p.suffix in (".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs") for p in iter_files(c.project))
    if has_js:
        cfg = [f for f in ESLINT_CONFIGS if (c.project / f).exists()] or (["package.json#eslintConfig"]
                                                                          if "eslintConfig" in c.pkg else [])
        eslint = which("eslint", c.project)
        if not cfg:
            c.record("eslint", "skipped", ["lint"], reason="projeto sem configuração ESLint (ver references/tool-matrix.md "
                                                          "para config sugerida; criar só com autorização)")
        elif not eslint:
            c.record("eslint", "not_installed", ["lint"], reason="eslint não instalado")
        else:
            cmd = [eslint, ".", "-f", "json"]
            r = run(cmd, c.project, c.timeout)
            c.raw("eslint.json", r["stdout"])
            findings = []
            try:
                data = json.loads(r["stdout"] or "[]")
            except json.JSONDecodeError:
                data = None
            if data is None:
                c.record("eslint", "failed", ["lint"], cmd=cmd, res=r, reason=(r["stderr"] or "saída inválida")[:300],
                         version=tool_version([eslint, "--version"], c.project))
            else:
                for fr in data:
                    for m in fr.get("messages", [])[:200]:
                        rid = m.get("ruleId") or "eslint-parse"
                        cat = ("security" if rid.startswith(("security/", "no-eval", "no-implied-eval", "no-new-func"))
                               else "integrity" if rid in ("no-undef", "no-unreachable", "no-dupe-keys", "eqeqeq",
                                                           "no-unsafe-finally", "no-fallthrough", "no-cond-assign",
                                                           "eslint-parse", "no-self-compare", "use-isnan",
                                                           "require-await", "no-async-promise-executor")
                               else "maintainability")
                        findings.append({"rule_id": f"eslint:{rid}", "title": f"ESLint {rid}",
                                         "severity": "MEDIUM" if m.get("severity") == 2 else "LOW",
                                         "status": "confirmed", "category": cat,
                                         "file": rel(c.project, Path(fr["filePath"])), "line": m.get("line", 1),
                                         "description": m.get("message", ""), "fix": "Ajustar conforme a regra.",
                                         "failure_mode": "Violação de regra de qualidade/correção.", "source": "eslint",
                                         "evidence": m.get("message", "")[:240]})
                c.record("eslint", "executed", ["lint"], cmd=cmd, res=r, findings=findings,
                         version=tool_version([eslint, "--version"], c.project))
        prettier = which("prettier", c.project)
        pcfg = any((c.project / f).exists() for f in (".prettierrc", ".prettierrc.json", ".prettierrc.js",
                                                      "prettier.config.js", ".prettierrc.yml")) or "prettier" in c.pkg
        if prettier and pcfg:
            cmd = [prettier, "--list-different", "."]
            r = run(cmd, c.project, c.timeout)
            files = [l for l in r["stdout"].splitlines() if l.strip()]
            fnd = ([{"rule_id": "prettier", "title": f"{len(files)} arquivo(s) fora do padrão Prettier",
                     "severity": "INFO", "status": "confirmed", "category": "maintainability",
                     "file": files[0], "line": 1, "description": ", ".join(files[:20]),
                     "fix": "prettier --write (com autorização)", "failure_mode": "Diffs ruidosos.",
                     "source": "prettier"}] if files else [])
            c.record("prettier", "executed", ["format"], cmd=cmd, res=r, findings=fnd,
                     version=tool_version([prettier, "--version"], c.project))
        else:
            c.record("prettier", "skipped" if prettier else "not_installed", ["format"],
                     reason="sem configuração Prettier" if prettier else "prettier não instalado")
    else:
        c.record("eslint", "not_applicable", ["lint"], reason="sem JS/TS")


# ------------------------------------------------------------------ dependências
NPM_SEV = {"critical": "CRITICAL", "high": "HIGH", "moderate": "MEDIUM", "low": "LOW", "info": "INFO"}


def deps(c: Ctx) -> None:
    if (c.project / "package.json").exists():
        npm = which("npm")
        lock = any((c.project / f).exists() for f in ("package-lock.json", "npm-shrinkwrap.json"))
        if not lock:
            other = [f for f in ("yarn.lock", "pnpm-lock.yaml") if (c.project / f).exists()]
            c.record("npm-audit", "skipped", ["deps"],
                     reason=(f"projeto usa {other[0]}: rode `yarn npm audit`/`pnpm audit --json` manualmente"
                             if other else "sem package-lock.json; versões resolvidas desconhecidas "
                                           "(gerar com `npm i --package-lock-only` somente com autorização)"))
        elif not npm:
            c.record("npm-audit", "not_installed", ["deps"], reason="npm não encontrado")
        else:
            cmd = [npm, "audit", "--json"]
            r = run(cmd, c.project, c.timeout)
            c.raw("npm-audit.json", r["stdout"])
            try:
                data = json.loads(r["stdout"] or "{}")
            except json.JSONDecodeError:
                data = {}
            if "vulnerabilities" not in data:
                c.record("npm-audit", "failed", ["deps"], cmd=cmd, res=r, version=tool_version([npm, "--version"], c.project),
                         reason=(data.get("error", {}).get("summary") if isinstance(data.get("error"), dict) else None)
                         or (r["stderr"] or "sem resposta do registry (rede?)")[:300])
            else:
                findings = []
                for name, v in data["vulnerabilities"].items():
                    advisories = [x for x in v.get("via", []) if isinstance(x, dict)]
                    titles = "; ".join(sorted({a.get("title", "") for a in advisories}))[:300] or \
                        f"vulnerável via {', '.join(x for x in v.get('via', []) if isinstance(x, str))}"
                    urls = ", ".join(sorted({a.get("url", "") for a in advisories if a.get("url")}))[:300]
                    cwes = sorted({cw for a in advisories for cw in a.get("cwe", [])})
                    fix = v.get("fixAvailable")
                    fixtxt = (f"Atualizar para {fix['name']}@{fix['version']}" + (" (MAJOR - pode quebrar API)"
                              if fix.get("isSemVerMajor") else "")) if isinstance(fix, dict) else \
                        ("`npm audit fix` resolve" if fix else "Sem correção publicada: avaliar substituição/mitigação")
                    findings.append({
                        "rule_id": f"npm-audit:{name}", "title": f"Dependência vulnerável: {name} ({v.get('range', '')})",
                        "severity": NPM_SEV.get(v.get("severity"), "MEDIUM"), "status": "confirmed",
                        "category": "security", "file": "package-lock.json", "line": 1,
                        "description": titles, "evidence": urls,
                        "failure_mode": "Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real "
                                        "depende de o código vulnerável ser alcançável pelo projeto.",
                        "likelihood": "depende da alcançabilidade" + (" (dependência direta)" if v.get("isDirect") else
                                                                      " (dependência transitiva)"),
                        "impact": "Conforme o advisory (ver links).", "fix": fixtxt, "source": "npm-audit",
                        "cwe": ", ".join(cwes), "owasp": "A06:2021 Vulnerable and Outdated Components"})
                c.record("npm-audit", "executed", ["deps"], cmd=cmd, res=r, findings=findings,
                         version=f"npm {tool_version([npm, '--version'], c.project)}",
                         extra={"metadata": data.get("metadata", {}).get("vulnerabilities")})
    else:
        c.record("npm-audit", "not_applicable", ["deps"], reason="sem package.json")
    reqs = [f for f in ("requirements.txt",) if (c.project / f).exists()]
    has_py = any(p.suffix == ".py" for p in iter_files(c.project))
    if has_py and not reqs and not (c.project / "pyproject.toml").exists():
        c.record("pip-audit", "skipped", ["deps"], reason="ha código Python mas nenhum requirements.txt/pyproject.toml: "
                                                        "dependências Python não declaradas nem auditáveis")
    if reqs or (c.project / "pyproject.toml").exists():
        pa = which("pip-audit")
        if not pa:
            c.record("pip-audit", "not_installed", ["deps"], reason="pip-audit não instalado (pip install pip-audit)")
        else:
            cmd = [pa, "-f", "json", "--progress-spinner", "off"] + (["-r", reqs[0]] if reqs else [str(c.project)])
            r = run(cmd, c.project, c.timeout)
            c.raw("pip-audit.json", r["stdout"])
            try:
                data = json.loads(r["stdout"] or "{}")
                depsl = data.get("dependencies", data if isinstance(data, list) else [])
            except json.JSONDecodeError:
                depsl = None
            if depsl is None:
                c.record("pip-audit", "failed", ["deps"], cmd=cmd, res=r, reason=r["stderr"][:300])
            else:
                findings = [{"rule_id": f"pip-audit:{d['name']}:{v['id']}",
                             "title": f"Dependência vulnerável: {d['name']} {d.get('version', '')} ({v['id']})",
                             "severity": "HIGH", "status": "confirmed", "category": "security",
                             "file": reqs[0] if reqs else "pyproject.toml", "line": 1,
                             "description": (v.get("description") or "")[:300],
                             "fix": f"Atualizar para {', '.join(v.get('fix_versions', [])) or 'versão corrigida'}",
                             "failure_mode": "Vulnerabilidade pública conhecida na dependência.",
                             "likelihood": "depende da alcançabilidade", "source": "pip-audit",
                             "owasp": "A06:2021"}
                            for d in depsl for v in d.get("vulns", [])]
                c.record("pip-audit", "executed", ["deps"], cmd=cmd, res=r, findings=findings,
                         version=tool_version([pa, "--version"], c.project))


# ------------------------------------------------------------------ SAST
SKILL_DIR = Path(__file__).resolve().parent.parent
LOCAL_SEMGREP_RULES = SKILL_DIR / "assets" / "semgrep" / "sentinel-rules.yml"
CRITICAL_CWES = ("CWE-89", "CWE-78", "CWE-95", "CWE-94", "CWE-502", "CWE-77")


def _reachable(url: str, timeout: float = 6.0) -> bool:
    """Sonda leve (HEAD) para evitar esperar minutos por um registry bloqueado."""
    import urllib.request
    try:
        urllib.request.urlopen(urllib.request.Request(url, method="HEAD"), timeout=timeout)
        return True
    except Exception as ex:  # noqa: BLE001 - qualquer falha = inacessível
        code = getattr(ex, "code", None)
        return code is not None and code < 500 and code != 403


def _semgrep(c: Ctx, sg: str, configs: list[str], timeout: int) -> tuple[dict, dict, list[str]]:
    cmd = [sg, "scan", "--disable-version-check", "--metrics=off", "--json", "--project-root", str(c.project)]
    for cfg in configs:
        cmd += ["--config", cfg]
    cmd += ["--exclude", "node_modules", "--exclude", ".code-sentinel", str(c.project)]
    r = run(cmd, c.project, timeout, env={"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"})
    try:
        data = json.loads(r["stdout"] or "{}")
    except json.JSONDecodeError:
        data = {}
    return r, data, cmd


def sast(c: Ctx) -> None:
    sg = which("semgrep")
    if not sg:
        c.record("semgrep", "not_installed", ["sast"], reason="semgrep não instalado (pip install semgrep)")
    else:
        data, r = {}, {"exit_code": None}
        note = "p/owasp-top-ten (registry) + ruleset local do Code Sentinel"
        if _reachable("https://semgrep.dev/c/p/owasp-top-ten"):
            r, data, cmd = _semgrep(c, sg, ["p/owasp-top-ten", str(LOCAL_SEMGREP_RULES)], min(c.timeout, 240))
        if "results" not in data or (r["exit_code"] not in (0, 1)):
            # registry inacessível (rede/política) -> ruleset local, que funciona offline
            r, data, cmd = _semgrep(c, sg, [str(LOCAL_SEMGREP_RULES)], c.timeout)
            note = "apenas ruleset local (registry semgrep.dev inacessível: sem rede ou bloqueado)"
        c.raw("semgrep.json", r["stdout"])
        if "results" not in data:
            errs = "; ".join(e.get("message", "")[:150] for e in data.get("errors", [])) if data else ""
            c.record("semgrep", "failed", ["sast"], cmd=cmd, res=r, version=tool_version([sg, "--version"], c.project),
                     reason=(errs or r["stderr"][-300:] or "sem saída").strip())
        else:
            findings = []
            for x in data["results"]:
                md = x["extra"].get("metadata", {}) or {}
                cwe = ", ".join(md.get("cwe", []) or [])[:120]
                level = x["extra"].get("severity")
                sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(level, "MEDIUM")
                if level == "ERROR" and any(k in cwe for k in CRITICAL_CWES):
                    sev = "CRITICAL"
                taint = "taint" in x["check_id"] or x["extra"].get("dataflow_trace") is not None
                status = "confirmed" if taint and str(md.get("confidence", "")).upper() == "HIGH" else "potential"
                findings.append({
                    "rule_id": f"semgrep:{x['check_id'].split('.')[-1]}", "title": x["extra"].get("message", "")[:110]
                    or x["check_id"].split(".")[-1], "severity": sev, "status": status, "category": "security",
                    "file": rel(c.project, c.project / x["path"]), "line": x["start"]["line"],
                    "description": x["extra"].get("message", "")[:400],
                    "failure_mode": ("Fluxo de dados comprovado da entrada da requisição até o ponto perigoso (taint)."
                                     if taint else "Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto)."),
                    "likelihood": "alta" if taint else "media",
                    "fix": x["extra"].get("fix") or "Ver mensagem da regra e references/audit-checklist.md.",
                    "source": "semgrep", "cwe": cwe,
                    "owasp": ", ".join(md.get("owasp", []) or [])[:120],
                    "evidence": (x["extra"].get("lines") or "")[:240]})
            c.record("semgrep", "executed", ["sast"], cmd=cmd, res=r, findings=findings,
                     version=tool_version([sg, "--version"], c.project), extra={"ruleset": note},
                     reason=note if "apenas" in note else None)
    for name in ("codeql", "snyk", "sonar-scanner"):
        if which(name):
            c.record(name, "skipped", ["sast"], reason=f"{name} disponível, mas requer configuração/autenticação do "
                                                      "projeto; execute conforme references/tool-matrix.md")


def python_tools(c: Ctx) -> None:
    has_py = any(p.suffix == ".py" for p in iter_files(c.project))
    if not has_py:
        return
    bandit = which("bandit")
    if not bandit:
        c.record("bandit", "not_installed", ["sast"], reason="bandit não instalado (pip install bandit)")
    else:
        cmd = [bandit, "-r", ".", "-f", "json", "-q", "-x", "./node_modules,./.venv,./venv,./.code-sentinel,./tests"]
        r = run(cmd, c.project, c.timeout)
        c.raw("bandit.json", r["stdout"])
        try:
            data = json.loads(r["stdout"] or "{}")
        except json.JSONDecodeError:
            data = {}
        sev = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        findings = [{"rule_id": f"bandit:{x['test_id']}", "title": f"{x['test_name']} ({x['test_id']})",
                     "severity": sev.get(x["issue_severity"], "LOW"),
                     "status": "confirmed" if x.get("issue_confidence") == "HIGH" else "potential",
                     "category": "security", "file": rel(c.project, c.project / x["filename"]), "line": x["line_number"],
                     "description": x["issue_text"], "failure_mode": "Ver documentação do bandit para o teste.",
                     "fix": x.get("more_info", ""), "source": "bandit",
                     "cwe": f"CWE-{x.get('issue_cwe', {}).get('id')}" if x.get("issue_cwe") else "",
                     "evidence": (x.get("code") or "")[:240]} for x in data.get("results", [])]
        c.record("bandit", "executed" if "results" in data else "failed", ["sast"], cmd=cmd, res=r,
                 findings=findings if "results" in data else None, version=tool_version([bandit, "--version"], c.project),
                 reason=None if "results" in data else r["stderr"][:300])
    ruff = which("ruff")
    if ruff:
        cmd = [ruff, "check", "--no-cache", "--output-format", "json", "--exit-zero", "."]
        r = run(cmd, c.project, c.timeout)
        try:
            data = json.loads(r["stdout"] or "[]")
        except json.JSONDecodeError:
            data = None
        if data is None:
            c.record("ruff", "failed", ["lint"], cmd=cmd, res=r, reason=r["stderr"][:300])
        else:
            findings = [{"rule_id": f"ruff:{x['code']}", "title": f"ruff {x['code']}",
                         "severity": "MEDIUM" if (x.get("code") or "").startswith(("F", "E9", "B")) else "LOW",
                         "status": "confirmed",
                         "category": "integrity" if (x.get("code") or "").startswith(("F", "E9", "B")) else "maintainability",
                         "file": rel(c.project, Path(x["filename"])), "line": x["location"]["row"],
                         "description": x["message"], "failure_mode": "Violação de lint.",
                         "fix": (x.get("fix") or {}).get("message") or "Ajustar conforme a regra.", "source": "ruff"}
                        for x in data[:300]]
            c.record("ruff", "executed", ["lint"], cmd=cmd, res=r, findings=findings,
                     version=tool_version([ruff, "--version"], c.project))
    else:
        c.record("ruff", "not_installed", ["lint"], reason="ruff não instalado")


# ------------------------------------------------------------------ testes
EDGE_KEYWORDS = {
    "vazio/nulo": r"\b(empty|vazi[oa]|null|undefined|None|nil)\b",
    "entrada inválida": r"\b(invalid|inv[aá]lid|malformed|NaN|negative|negativ)",
    "limites": r"\b(boundary|limit|limite|max|min|overflow|large|grande|huge)\b",
    "concorrência": r"\b(concurr|parallel|simult|race|Promise\.all)\b",
    "falha externa": r"\b(timeout|ECONNREFUSED|unavailable|indispon|network|reject|503|502|500)\b",
    "auth/permissão": r"\b(401|403|unauthori[sz]ed|forbidden|permission|permiss)\b",
    "duplicados": r"\b(duplicate|duplicad|idempot)\b",
}


def edge_case_coverage(c: Ctx) -> dict:
    found = {}
    for p in iter_files(c.project):
        r = rel(c.project, p)
        if not is_test_file(r):
            continue
        txt = read_text(p) or ""
        for k, rx in EDGE_KEYWORDS.items():
            if k not in found and re.search(rx, txt, re.I):
                found[k] = r
    return found


def tests(c: Ctx, enabled: bool) -> dict:
    t = {"executed": False, "framework": None, "total": 0, "passed": 0, "failed": 0, "skipped": 0,
         "coverage": None, "failures": [], "reason": None,
         "test_files": sum(1 for p in iter_files(c.project) if is_test_file(rel(c.project, p)))}
    edge = edge_case_coverage(c)
    t["edge_case_categories"] = sorted(edge)
    if t["test_files"] == 0:
        t["reason"] = "nenhum arquivo de teste encontrado no projeto"
        c.record("tests", "not_applicable", ["tests_executed"], reason=t["reason"])
        return t
    if not enabled:
        t["reason"] = "execução de testes não autorizada (use --run-tests)"
        c.record("tests", "skipped", ["tests_executed"], reason=t["reason"])
        return t
    script = (c.pkg.get("scripts") or {}).get("test", "")
    runner = None
    if "vitest" in c.js_deps and which("vitest", c.project):
        runner = "vitest"
    elif "jest" in c.js_deps and which("jest", c.project):
        runner = "jest"
    elif "mocha" in c.js_deps and which("mocha", c.project):
        runner = "mocha"
    elif "node --test" in script:
        runner = "node:test"
    elif any(p.suffix == ".py" for p in iter_files(c.project)) and which("python3"):
        runner = "pytest"
    elif script and "no test specified" not in script and which("npm"):
        runner = "npm-test"
    t["framework"] = runner
    if runner is None:
        decl = [k for k in ("jest", "vitest", "mocha") if k in c.js_deps]
        t["reason"] = (f"{decl[0]} declarado mas não instalado (node_modules ausente?)" if decl
                       else "nenhum test runner reconhecido/instalado")
        c.record("tests", "not_installed", ["tests_executed"], reason=t["reason"])
        return t
    raw = c.out / "raw"
    res = None
    if runner == "jest":
        cmd = [which("jest", c.project), "--ci", "--json", f"--outputFile={raw / 'jest.json'}", "--coverage",
               "--coverageReporters=json-summary", f"--coverageDirectory={raw / 'coverage-jest'}"]
        res = run(cmd, c.project, c.timeout)
        _parse_jest_like(t, load_json(raw / "jest.json", {}) or {})
        _coverage_summary(t, raw / "coverage-jest" / "coverage-summary.json")
    elif runner == "vitest":
        base = [which("vitest", c.project), "run", "--reporter=json", f"--outputFile={raw / 'vitest.json'}"]
        cmd = base + ["--coverage.enabled=true", "--coverage.reporter=json-summary",
                      f"--coverage.reportsDirectory={raw / 'coverage-vitest'}"]
        res = run(cmd, c.project, c.timeout)
        if not (raw / "vitest.json").exists():  # provider de cobertura ausente: roda sem cobertura
            cmd = base
            res = run(cmd, c.project, c.timeout)
        _parse_jest_like(t, load_json(raw / "vitest.json", {}) or {})
        _coverage_summary(t, raw / "coverage-vitest" / "coverage-summary.json")
    elif runner == "mocha":
        c8 = which("c8", c.project)
        cmd = ([c8, "--reporter=json-summary", f"--reports-dir={raw / 'coverage-c8'}"] if c8 else []) + \
              [which("mocha", c.project), "--reporter", "json"]
        res = run(cmd, c.project, c.timeout)
        try:
            data = json.loads(res["stdout"][res["stdout"].find("{"):] or "{}")
        except json.JSONDecodeError:
            data = {}
        st = data.get("stats", {})
        t.update(total=st.get("tests", 0), passed=st.get("passes", 0), failed=st.get("failures", 0),
                 skipped=st.get("pending", 0))
        t["failures"] = [{"name": f.get("fullTitle"), "message": (f.get("err") or {}).get("message", "")[:300],
                          "file": f.get("file")} for f in data.get("failures", [])]
        _coverage_summary(t, raw / "coverage-c8" / "coverage-summary.json")
    elif runner == "node:test":
        args = script.split("node --test", 1)[1].split("&&")[0].split() if "node --test" in script else []
        args = [a for a in args if not a.startswith("--test-reporter")]
        cmd = [which("node"), "--test", "--test-reporter=tap", "--experimental-test-coverage"] + args
        res = run(cmd, c.project, c.timeout)
        _parse_tap(t, res["stdout"])
    elif runner == "pytest":
        cov = run([which("python3"), "-c", "import pytest_cov"], c.project, 30)["exit_code"] == 0
        cmd = [which("python3"), "-m", "pytest", "-q", "-p", "no:cacheprovider", f"--junitxml={raw / 'pytest.xml'}"] + \
              ([f"--cov={c.project}", f"--cov-report=json:{raw / 'coverage-py.json'}"] if cov else [])
        res = run(cmd, c.project, c.timeout)
        _parse_junit(t, raw / "pytest.xml")
        cj = load_json(raw / "coverage-py.json", {}) or {}
        if cj.get("totals"):
            t["coverage"] = {"lines": round(cj["totals"].get("percent_covered", 0), 2), "branches": None,
                             "functions": None, "source": "pytest-cov"}
            t["_per_file"] = {k: v.get("summary", {}).get("percent_covered", 0) for k, v in cj.get("files", {}).items()}
    else:
        cmd = [which("npm"), "test", "--silent"]
        res = run(cmd, c.project, c.timeout)
        t["reason"] = "runner genérico: apenas o código de saída foi usado (sem contagem de testes)"
        if res["exit_code"] == 0:
            t.update(total=1, passed=1)
        else:
            t.update(total=1, failed=1, failures=[{"name": "npm test", "message": (res["stdout"] + res["stderr"])[-400:]}])
    effective_coverage(c, t, ("py",) if runner == "pytest" else ("js", "cjs", "mjs", "jsx", "ts", "tsx", "mts", "cts"))
    t.pop("_per_file", None)
    for f in t["failures"]:
        if f.get("file"):
            fp = Path(str(f["file"]).replace("file://", ""))
            f["file"] = rel(c.project, fp if fp.is_absolute() else c.project / fp)
    c.raw("tests-output.txt", (res["stdout"] if res else "") + "\n--- stderr ---\n" + (res["stderr"] if res else ""))
    t["executed"] = t["total"] > 0
    t["exit_code"] = res["exit_code"] if res else None
    if res and res["timed_out"]:
        t["reason"] = f"timeout apos {c.timeout}s"
    if not t["executed"]:
        t["reason"] = t["reason"] or "runner executou mas nenhum teste foi contabilizado (ver raw/tests-output.txt)"
    findings = [{"rule_id": "TEST-FAILING", "title": f"Teste falhando: {f.get('name')}", "severity": "HIGH",
                 "status": "confirmed", "category": "tests", "file": f.get("file") or "(suite de testes)", "line": 1,
                 "description": f.get("message") or "", "failure_mode": "Comportamento esperado pela suite não e "
                 "atendido: ou ha bug no código, ou o teste esta desatualizado. Não ignorar.",
                 "likelihood": "certa", "fix": "Investigar a causa raiz; corrigir o código ou o teste (nunca desabilitar).",
                 "source": f"tests:{runner}", "scored_via": "pass_rate"} for f in t["failures"]]
    c.record("tests", "executed" if t["executed"] else "failed",
             ["tests_executed"] + (["coverage"] if t["coverage"] else []) +
             (["edge_case_tests"] if t["executed"] and len(edge) >= 3 else []),
             version=runner, cmd=[x for x in cmd if x], res=res, findings=findings, reason=t["reason"],
             extra={"summary": {k: t[k] for k in ("total", "passed", "failed", "skipped")}})
    return t


def _parse_jest_like(t: dict, data: dict) -> None:
    t.update(total=data.get("numTotalTests", 0), passed=data.get("numPassedTests", 0),
             failed=data.get("numFailedTests", 0), skipped=data.get("numPendingTests", 0) + data.get("numTodoTests", 0))
    for suite in data.get("testResults", []):
        for a in suite.get("assertionResults", []):
            if a.get("status") == "failed":
                t["failures"].append({"name": a.get("fullName") or a.get("title"),
                                      "message": " ".join(a.get("failureMessages") or [])[:400],
                                      "file": suite.get("name")})
        if suite.get("status") == "failed" and not suite.get("assertionResults"):
            t["failures"].append({"name": f"suite {suite.get('name')}", "message": (suite.get("message") or "")[:400],
                                  "file": suite.get("name")})
            t["failed"] += 1
            t["total"] += 1


def _coverage_summary(t: dict, p: Path) -> None:
    d = load_json(p, None)
    if d and "total" in d:
        tot = d["total"]
        t["coverage"] = {"lines": tot["lines"]["pct"], "branches": tot["branches"]["pct"],
                         "functions": tot["functions"]["pct"], "statements": tot["statements"]["pct"],
                         "source": p.parent.name}
        t["_per_file"] = {k: v["lines"]["pct"] for k, v in d.items() if k != "total"}


def effective_coverage(c: Ctx, t: dict, langs: tuple[str, ...]) -> None:
    """Runners costumam medir só os arquivos CARREGADOS pelos testes. Recalcula a cobertura de linhas
    sobre TODO o código-fonte da linguagem (arquivos nunca importados contam como 0%)."""
    per = t.pop("_per_file", None)
    if not t.get("coverage") or per is None:
        return
    per_rel = {}
    for k, v in per.items():
        kp = Path(k)
        per_rel[rel(c.project, kp if kp.is_absolute() else c.project / kp)] = v
    total_loc = covered = 0.0
    uncovered_files = []
    for p in iter_files(c.project):
        if p.suffix.lstrip(".") not in langs:
            continue
        r = rel(c.project, p)
        if is_test_path(r) or re.search(r"\.config\.[cm]?[jt]s$|(^|/)(conftest|setup)\.py$", r):
            continue
        loc = sum(1 for l in (read_text(p) or "").splitlines() if l.strip())
        total_loc += loc
        if r in per_rel:
            covered += loc * (per_rel[r] or 0) / 100
        else:
            uncovered_files.append(r)
    if total_loc:
        cov = t["coverage"]
        cov["lines_reported"] = cov["lines"]
        cov["lines"] = round(100 * covered / total_loc, 1)
        cov["files_never_loaded"] = uncovered_files[:50]
        cov["note"] = ("cobertura efetiva: arquivos-fonte nunca carregados pelos testes contam como 0% "
                       f"({len(uncovered_files)} arquivo(s)); valor reportado pelo runner: {cov['lines_reported']}%")


def _parse_tap(t: dict, out: str) -> None:
    def num(key):
        m = re.search(rf"^# {key} (\d+)", out, re.M)
        return int(m.group(1)) if m else 0
    t.update(total=num("tests"), passed=num("pass"), failed=num("fail"), skipped=num("skipped") + num("todo"))
    lines = out.splitlines()
    for i, l in enumerate(lines):
        m = re.match(r"^(\s*)not ok \d+ - (.+)$", l)
        if m:
            block = "\n".join(lines[i + 1:i + 25])
            if re.search(r"failureType: '(subtestsFailed|cancelledByParent)'", block):
                continue  # suite que falhou por causa de um subteste (ja contado)
            msg = re.search(r"error: \|?-?\s*\n?\s*(.+)", block)
            loc = re.search(r"location: '([^']+)'", block)
            t["failures"].append({"name": m.group(2).strip(), "message": msg.group(1).strip()[:300] if msg else "",
                                  "file": loc.group(1).rsplit(":", 2)[0] if loc else None})
    m = re.search(r"^# all files\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)\s*\|\s*([\d.]+)", out, re.M)
    if m:
        t["coverage"] = {"lines": float(m.group(1)), "branches": float(m.group(2)), "functions": float(m.group(3)),
                         "source": "node --experimental-test-coverage"}
        per, stack, inside = {}, [], False
        for l in lines:
            if re.match(r"^# file\s*\|", l):
                inside = True
                continue
            if not inside or not l.startswith("# ") or l.startswith("# ---"):
                continue
            if l.startswith("# all files"):
                break
            cells = [x.strip() for x in l[2:].split("|")]
            raw_name = l[2:].split("|")[0]
            depth = len(raw_name) - len(raw_name.lstrip(" "))
            name = cells[0]
            stack = stack[:depth]
            if len(cells) > 1 and cells[1]:
                try:
                    per["/".join(stack + [name])] = float(cells[1])
                except ValueError:
                    pass
            else:
                stack.append(name)
        t["_per_file"] = per


def _parse_junit(t: dict, p: Path) -> None:
    try:
        root = ET.parse(p).getroot()
    except (OSError, ET.ParseError):
        return
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    for s in suites:
        total = int(s.get("tests", 0))
        fail = int(s.get("failures", 0)) + int(s.get("errors", 0))
        skip = int(s.get("skipped", 0))
        t["total"] += total
        t["failed"] += fail
        t["skipped"] += skip
        t["passed"] += total - fail - skip
        for tc in s.iter("testcase"):
            f = tc.find("failure") if tc.find("failure") is not None else tc.find("error")
            if f is not None:
                t["failures"].append({"name": f"{tc.get('classname')}::{tc.get('name')}",
                                      "message": (f.get("message") or "")[:300], "file": tc.get("file")})


# ------------------------------------------------------------------ main
GROUPS = ["syntax", "types", "lint", "deps", "sast", "python", "tests"]


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--out")
    ap.add_argument("--run-tests", action="store_true", help="executa a suite de testes do projeto")
    ap.add_argument("--only", default="", help="grupos separados por virgula")
    ap.add_argument("--skip", default="", help="grupos a pular")
    ap.add_argument("--timeout", type=int, default=600)
    a = ap.parse_args()
    project = Path(a.project).resolve()
    d = out_dir(project, a.out)
    c = Ctx(project, d, a.timeout)
    only = {x for x in a.only.split(",") if x}
    skip = {x for x in a.skip.split(",") if x}
    sel = [g for g in GROUPS if (not only or g in only) and g not in skip]
    test_ev = None
    for g in sel:
        if g == "syntax":
            syntax(c)
        elif g == "types":
            types(c)
        elif g == "lint":
            lint(c)
        elif g == "deps":
            deps(c)
        elif g == "sast":
            sast(c)
        elif g == "python":
            python_tools(c)
        elif g == "tests":
            test_ev = tests(c, a.run_tests)
    save_evidence(d, "tools", {"generated_at": now_iso(), "tools": c.tools,
                               "checks": sorted({ch for t in c.tools for ch in t["checks"]})})
    if test_ev is not None:
        save_evidence(d, "tests", test_ev)
    print(f"[tools] evidências -> {d / 'evidence'}")


if __name__ == "__main__":
    main()
