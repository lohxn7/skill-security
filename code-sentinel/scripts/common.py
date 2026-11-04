"""Utilitarios compartilhados pelos scripts do CODE SENTINEL.

Formato de achado (finding) -- usado por todos os scanners e pela revisão manual:

{
  "id": "SEC-001",                # gerado se ausente
  "rule_id": "JS-SQL-CONCAT",     # identifica a regra/ferramenta de origem
  "title": "Nome do problema",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "status": "confirmed|potential|hypothesis",
  "category": "tests|security|integrity|stability|performance|maintainability",
  "file": "src/app.js", "line": 42, "end_line": 44,
  "description": "O que esta acontecendo",
  "failure_mode": "Como isso quebra o sistema",
  "likelihood": "alta|media|baixa|desconhecida",
  "impact": "Impacto potencial",
  "fix": "Sugestão de correção",
  "fixed_code": "exemplo de código corrigido (opcional)",
  "source": "pattern-scan|secret-scan|npm-audit|eslint|tsc|manual|...",
  "evidence": "trecho/saída que comprova (secrets sempre mascarados)",
  "cwe": "CWE-89", "owasp": "A03:2021",
  "in_test_code": false
}
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Iterator

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_PT = {
    "CRITICAL": "CRÍTICO", "HIGH": "ALTO", "MEDIUM": "MÉDIO", "LOW": "BAIXO", "INFO": "INFORMATIVO",
}
STATUSES = ["confirmed", "potential", "hypothesis"]
# status de triagem: removem o achado da nota (exigem "justification")
RESOLVED_STATUSES = ["false_positive", "fixed", "accepted_risk"]
STATUS_PT = {"confirmed": "Confirmado", "potential": "Risco potencial", "hypothesis": "Hipótese"}
CATEGORIES = ["tests", "security", "integrity", "stability", "performance", "maintainability"]
CATEGORY_PT = {
    "tests": "Testes automatizados",
    "security": "Segurança e vulnerabilidades",
    "integrity": "Integridade e lógica",
    "stability": "Estabilidade e tratamento de erros",
    "performance": "Performance",
    "maintainability": "Manutenibilidade",
}

IGNORED_DIRS = {
    ".git", "node_modules", "dist", "build", "out", "coverage", ".next", ".nuxt", ".svelte-kit",
    ".venv", "venv", "env", "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox",
    "vendor", "target", ".idea", ".vscode", ".code-sentinel", ".turbo", ".cache", "bower_components",
    "site-packages", ".gradle",
}
SOURCE_EXT = {
    ".js": "js", ".mjs": "js", ".cjs": "js", ".jsx": "js", ".ts": "ts", ".tsx": "ts", ".mts": "ts",
    ".cts": "ts", ".py": "py", ".go": "go", ".java": "java", ".kt": "kotlin", ".rb": "ruby",
    ".php": "php", ".cs": "csharp", ".rs": "rust", ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp",
    ".swift": "swift", ".scala": "scala", ".vue": "vue", ".svelte": "svelte", ".sh": "shell",
    ".sql": "sql", ".dart": "dart",
}
TEST_PATH_RE = re.compile(
    r"(^|/)(__tests__|tests?|spec|specs|e2e|cypress|fixtures?|__mocks__)(/|$)|"
    r"\.(test|spec|e2e|cy)\.[a-z]+$|(^|/)test_[^/]+\.py$|_test\.(py|go)$",
    re.I,
)
MAX_FILE_BYTES = 1_500_000


def now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


TEST_FILE_RE = re.compile(
    r"\.(test|spec|e2e|cy)\.[cm]?[jt]sx?$|(^|/)test_[^/]+\.py$|_test\.(py|go)$|"
    r"(^|/)(__tests__|tests?|spec|e2e|cypress)/(?!(?:[^/]+/)*(fixtures?|__mocks__|helpers?)/)(?:[^/]+/)*[^/]+\.([cm]?[jt]sx?|py)$",
    re.I,
)


def is_test_file(rel: str) -> bool:
    """Arquivo que contem testes de fato (fixtures e mocks não contam)."""
    return bool(TEST_FILE_RE.search(rel.replace(os.sep, "/")))


def is_test_path(rel: str) -> bool:
    return bool(TEST_PATH_RE.search(rel.replace(os.sep, "/")))


def iter_files(root: Path, extra_ignores: Iterable[str] = ()) -> Iterator[Path]:
    """Percorre o projeto ignorando dependências, builds e o proprio diretório de saída."""
    ignores = IGNORED_DIRS | set(extra_ignores)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ignores and not d.startswith(".code-sentinel")]
        for fn in filenames:
            p = Path(dirpath) / fn
            try:
                if p.is_symlink() or p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def read_text(p: Path) -> str | None:
    try:
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None  # binário
    return data.decode("utf-8", errors="replace")


def rel(root: Path, p: Path) -> str:
    try:
        return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()


def load_json(p: Path, default=None):
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def write_json(p: Path, data) -> None:
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def out_dir(project: Path, out: str | None) -> Path:
    d = Path(out) if out else project / ".code-sentinel"
    d.mkdir(parents=True, exist_ok=True)
    (d / "findings").mkdir(exist_ok=True)
    (d / "evidence").mkdir(exist_ok=True)
    (d / "raw").mkdir(exist_ok=True)
    gi = d / ".gitignore"
    if not gi.exists():
        # relatorios podem conter trechos de código sensível: não versionar por padrão
        gi.write_text("*\n", encoding="utf-8")
    return d


def mask_secret(s: str) -> str:
    s = s.strip()
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}{'*' * min(12, len(s) - 6)}{s[-2:]}"


def which(name: str, project: Path | None = None) -> str | None:
    """Procura primeiro em node_modules/.bin do projeto, depois no PATH. Nunca instala nada."""
    if project is not None:
        local = project / "node_modules" / ".bin" / name
        if local.exists():
            return str(local)
    return shutil.which(name)


def run(cmd: list[str], cwd: Path, timeout: int = 300, env: dict | None = None) -> dict:
    """Executa um comando sem shell, com timeout, capturando saída. Não lanca exceção."""
    start = _dt.datetime.now()
    e = os.environ.copy()
    e.setdefault("CI", "true")
    e.setdefault("NO_COLOR", "1")
    e.setdefault("FORCE_COLOR", "0")
    e.setdefault("SEMGREP_ENABLE_VERSION_CHECK", "0")  # evita esperar a rede em `semgrep --version`
    if env:
        e.update(env)
    try:
        cp = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout,
                            env=e, stdin=subprocess.DEVNULL)
        code, out, err, to = cp.returncode, cp.stdout, cp.stderr, False
    except subprocess.TimeoutExpired as ex:
        code, out, err, to = None, (ex.stdout or b"").decode() if isinstance(ex.stdout, bytes) else (ex.stdout or ""), \
            (ex.stderr or b"").decode() if isinstance(ex.stderr, bytes) else (ex.stderr or ""), True
    except FileNotFoundError as ex:
        code, out, err, to = 127, "", str(ex), False
    dur = (_dt.datetime.now() - start).total_seconds()
    return {"cmd": cmd, "exit_code": code, "stdout": out, "stderr": err, "timed_out": to,
            "duration_s": round(dur, 2)}


def tool_version(cmd: list[str], cwd: Path) -> str | None:
    r = run(cmd, cwd, timeout=30)
    if r["exit_code"] not in (0,):
        return None
    txt = (r["stdout"] or r["stderr"]).strip().splitlines()
    return txt[0].strip() if txt else None


def finalize_findings(findings: list[dict], prefix: str) -> list[dict]:
    """Normaliza campos obrigatorios e gera IDs estáveis."""
    out = []
    for i, f in enumerate(findings, 1):
        f = dict(f)
        f.setdefault("id", f"{prefix}-{i:03d}")
        f["severity"] = f.get("severity", "INFO").upper()
        if f["severity"] not in SEVERITIES:
            f["severity"] = "INFO"
        if f.get("status") not in STATUSES:
            f["status"] = "potential"
        if f.get("category") not in CATEGORIES:
            f["category"] = "integrity"
        f.setdefault("likelihood", "desconhecida")
        out.append(f)
    return out


def save_findings(d: Path, source: str, findings: list[dict]) -> Path:
    p = d / "findings" / f"{source}.json"
    write_json(p, {"source": source, "generated_at": now_iso(), "findings": findings})
    return p


def save_evidence(d: Path, name: str, evidence: dict) -> Path:
    p = d / "evidence" / f"{name}.json"
    evidence.setdefault("generated_at", now_iso())
    write_json(p, evidence)
    return p


def load_all(d: Path) -> tuple[list[dict], list[dict]]:
    findings, evidence = [], []
    for p in sorted((d / "findings").glob("*.json")):
        data = load_json(p, {}) or {}
        items = data.get("findings", data if isinstance(data, list) else [])
        for f in items:
            if not isinstance(f, dict):
                continue
            f.setdefault("source", data.get("source", p.stem) if isinstance(data, dict) else p.stem)
            f["severity"] = str(f.get("severity", "INFO")).upper()
            if f["severity"] not in SEVERITIES:
                f["severity"] = "INFO"
            if f.get("status") not in STATUSES + RESOLVED_STATUSES:
                f["status"] = "potential"
            if f.get("category") not in CATEGORIES:
                f["category"] = "integrity"
            f.setdefault("title", f.get("rule_id") or "Achado sem título")
            findings.append(f)
    for p in sorted((d / "evidence").glob("*.json")):
        data = load_json(p, None)
        if isinstance(data, dict):
            data.setdefault("name", p.stem)
            evidence.append(data)
    return findings, evidence
