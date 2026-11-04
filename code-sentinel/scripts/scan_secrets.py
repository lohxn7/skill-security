#!/usr/bin/env python3
"""Varredura de credenciais e segredos expostos no código-fonte.

Uso:
    python3 scripts/scan_secrets.py <projeto> [--out DIR]

* Somente leitura. Os valores encontrados são SEMPRE mascarados na saída
  (o relatório nunca deve redistribuir um segredo).
* Tambem verifica se arquivos .env estão versionados no git.
Saída: <out>/findings/secret-scan.json e <out>/evidence/secret-scan.json
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (finalize_findings, is_test_path, iter_files, mask_secret, out_dir, read_text, rel,  # noqa: E402
                    save_evidence, save_findings)

# (id, título, regex, severidade, grupo do valor)
PATTERNS = [
    ("SECRET-PRIVATE-KEY", "Chave privada embutida no repositório",
     re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "CRITICAL", 0),
    ("SECRET-AWS-ACCESS-KEY", "AWS Access Key ID exposta",
     re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16})\b"), "CRITICAL", 1),
    ("SECRET-AWS-SECRET-KEY", "AWS Secret Access Key exposta",
     re.compile(r"(?i)aws.{0,25}(?:secret|private).{0,25}['\"]([A-Za-z0-9/+=]{40})['\"]"), "CRITICAL", 1),
    ("SECRET-GITHUB-TOKEN", "Token do GitHub exposto",
     re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"), "CRITICAL", 1),
    ("SECRET-SLACK-TOKEN", "Token do Slack exposto",
     re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"), "HIGH", 1),
    ("SECRET-STRIPE-KEY", "Chave secreta do Stripe exposta",
     re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), "CRITICAL", 1),
    ("SECRET-GOOGLE-API-KEY", "Google API key exposta",
     re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"), "HIGH", 1),
    ("SECRET-AI-API-KEY", "Chave de API de provedor de IA exposta",
     re.compile(r"\b(sk-ant-[A-Za-z0-9_\-]{20,}|sk-(?:proj-)?[A-Za-z0-9]{32,})\b"), "CRITICAL", 1),
    ("SECRET-SENDGRID-KEY", "Chave do SendGrid exposta",
     re.compile(r"\b(SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43})\b"), "HIGH", 1),
    ("SECRET-JWT-LITERAL", "JWT literal embutido no código",
     re.compile(r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"), "MEDIUM", 1),
    ("SECRET-DB-URL", "URL de banco de dados com senha embutida",
     re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s'\"/]+:([^@\s'\"]{3,})@[^\s'\"]+)"), "HIGH", 2),
    ("SECRET-HARDCODED", "Credencial hardcoded (senha/segredo/token literal)",
     re.compile(r"(?i)\b([A-Za-z0-9_]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
                r"private[_-]?key|client[_-]?secret|jwt[_-]?secret|session[_-]?secret)[A-Za-z0-9_]*)\b['\"]?\s*[:=]\s*"
                r"['\"`]([^'\"`\s]{6,})['\"`]"), "HIGH", 2),
]
PLACEHOLDER_RE = re.compile(
    r"(?i)^(x{3,}|\*+|<[^>]+>|\$\{[^}]+\}|\{\{[^}]+\}\}|%\(?\w+\)?s?|your[_-]?.*|example.*|dummy.*|placeholder.*|"
    r"test(ing)?|fake.*|sample.*|redacted|null|none|undefined|process\.env.*|os\.environ.*|env\(.*|change[_-]?it|"
    r"\.\.\.|password|secret|todo)$"
)
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".lock", ".min.js", ".map", ".woff", ".woff2", ".pdf"}
SKIP_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock", "go.sum", "Cargo.lock"}
IGNORE_MARK = "sentinel-ignore"


def _ignored(lines: list[str], ln: int) -> bool:
    """Suprime a linha se o marcador estiver nela ou numa linha ANTERIOR que seja so comentário."""
    if IGNORE_MARK in lines[ln - 1]:
        return True
    if ln > 1:
        prev = lines[ln - 2].strip()
        return IGNORE_MARK in prev and prev.startswith(("//", "#", "/*", "*"))
    return False


def scan(project: Path) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    files = 0
    for p in iter_files(project):
        if p.name in SKIP_NAMES or p.suffix.lower() in SKIP_EXT or p.name.endswith(".min.js"):
            continue
        text = read_text(p)
        if text is None:
            continue
        files += 1
        r = rel(project, p)
        in_test = is_test_path(r)
        lines = text.splitlines()
        for ln, line in enumerate(lines, 1):
            if _ignored(lines, ln):
                continue
            if len(line) > 2000:
                line = line[:2000]
            seen_on_line = set()
            for rid, title, rx, sev, grp in PATTERNS:
                for m in rx.finditer(line):
                    value = m.group(grp) if grp else m.group(0)
                    if rid == "SECRET-HARDCODED":
                        if PLACEHOLDER_RE.match(value) or value.lower() == m.group(1).lower():
                            continue
                        # ja reportado por padrão específico na mesma linha
                        if seen_on_line:
                            continue
                    seen_on_line.add(rid)
                    s = sev
                    if in_test and s in ("CRITICAL", "HIGH"):
                        s = "MEDIUM"  # segredo em teste/fixture: ainda vaza, mas tende a ser falso
                    findings.append({
                        "rule_id": rid,
                        "title": title,
                        "severity": s,
                        "status": "confirmed",
                        "category": "security",
                        "file": r,
                        "line": ln,
                        "description": f"Valor sensível literal encontrado ({mask_secret(value)}).",
                        "failure_mode": "Qualquer pessoa com acesso ao código, ao histórico git ou ao bundle "
                                        "pode usar a credencial para acessar o serviço/dados protegidos.",
                        "likelihood": "alta" if not in_test else "media",
                        "impact": "Acesso não autorizado, movimentação lateral, custo financeiro, vazamento de dados.",
                        "fix": "Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois "
                               "permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.",
                        "fixed_code": _fixed_example(p.suffix.lower(), m.group(1) if rid == "SECRET-HARDCODED" else None),
                        "source": "secret-scan",
                        "evidence": _redact(line.strip(), value)[:240],
                        "cwe": "CWE-798",
                        "owasp": "A07:2021 / ASVS V2.10, V6.4",
                        "in_test_code": in_test,
                    })
    findings += env_files_tracked(project)
    ev = {"tool": "scan_secrets.py", "version": "1.0", "status": "executed", "checks": ["secrets"],
          "files_scanned": files, "rules": len(PATTERNS)}
    return finalize_findings(findings, "SECRET"), ev


def _redact(line: str, value: str) -> str:
    return line.replace(value, mask_secret(value)) if value else line


def _fixed_example(ext: str, var: str | None) -> str:
    name = (var or "API_KEY").upper()
    if ext == ".py":
        return f'import os\n{(var or "api_key")} = os.environ["{name}"]  # falha cedo se ausente'
    if ext in (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"):
        return (f"const {var or 'apiKey'} = process.env.{name};\n"
                f"if (!{var or 'apiKey'}) throw new Error('{name} não configurada');")
    return f"Ler {name} de variável de ambiente ou cofre de segredos."


def env_files_tracked(project: Path) -> list[dict]:
    out = []
    try:
        cp = subprocess.run(["git", "ls-files", "-z"], cwd=project, capture_output=True, timeout=30)
        tracked = [t for t in cp.stdout.decode(errors="replace").split("\0") if t] if cp.returncode == 0 else []
    except (OSError, subprocess.TimeoutExpired):
        tracked = []
    for t in tracked:
        name = t.rsplit("/", 1)[-1]
        if re.fullmatch(r"\.env(\.(?!example|sample|template|dist)[\w.-]+)?", name):
            out.append({
                "rule_id": "SECRET-ENV-TRACKED", "title": "Arquivo .env versionado no git", "severity": "HIGH",
                "status": "confirmed", "category": "security", "file": t, "line": 1,
                "description": "Arquivo de ambiente com possíveis segredos esta rastreado pelo git.",
                "failure_mode": "Segredos ficam no histórico do repositório e em todos os clones.",
                "likelihood": "alta", "impact": "Exposição de credenciais de todos os ambientes.",
                "fix": "git rm --cached <arquivo>, adicionar ao .gitignore, rotacionar segredos, "
                       "versionar apenas um .env.example sem valores.",
                "source": "secret-scan", "cwe": "CWE-538", "owasp": "A05:2021",
            })
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--out")
    a = ap.parse_args()
    project = Path(a.project)
    d = out_dir(project, a.out)
    findings, ev = scan(project)
    ev["findings"] = len(findings)
    save_findings(d, "secret-scan", findings)
    save_evidence(d, "secret-scan", ev)
    print(f"[secrets] {ev['files_scanned']} arquivos, {len(findings)} achados -> {d / 'findings' / 'secret-scan.json'}")


if __name__ == "__main__":
    main()
