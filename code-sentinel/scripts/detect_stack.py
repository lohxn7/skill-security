#!/usr/bin/env python3
"""Detecta linguagens, frameworks, ferramentas de teste/qualidade e o que esta instalado.

Uso:
    python3 scripts/detect_stack.py <projeto> [--out DIR]

Somente leitura: não instala nada e não executa código do projeto
(apenas `--version` de ferramentas ja instaladas).
Saída: <out>/stack.json (padrão <projeto>/.code-sentinel/stack.json)
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (SOURCE_EXT, is_test_file, iter_files, load_json, now_iso, out_dir, rel,  # noqa: E402
                    tool_version, which, write_json)

JS_FRAMEWORKS = {
    "express": "Express", "fastify": "Fastify", "koa": "Koa", "@nestjs/core": "NestJS", "hapi": "hapi",
    "@hapi/hapi": "hapi", "next": "Next.js", "react": "React", "vue": "Vue", "nuxt": "Nuxt",
    "@angular/core": "Angular", "svelte": "Svelte", "electron": "Electron", "react-native": "React Native",
    "graphql": "GraphQL", "prisma": "Prisma", "@prisma/client": "Prisma", "mongoose": "Mongoose",
    "sequelize": "Sequelize", "typeorm": "TypeORM", "pg": "PostgreSQL (pg)", "mysql": "MySQL",
    "mysql2": "MySQL", "sqlite3": "SQLite", "better-sqlite3": "SQLite", "jsonwebtoken": "JWT",
    "passport": "Passport", "socket.io": "Socket.IO",
}
JS_TEST_TOOLS = {
    "jest": "Jest", "vitest": "Vitest", "mocha": "Mocha", "chai": "Chai", "ava": "AVA", "jasmine": "Jasmine",
    "@testing-library/react": "Testing Library", "@testing-library/vue": "Testing Library",
    "@testing-library/dom": "Testing Library", "@testing-library/jest-dom": "Testing Library",
    "cypress": "Cypress", "@playwright/test": "Playwright", "playwright": "Playwright",
    "supertest": "Supertest", "nyc": "nyc (cobertura)", "c8": "c8 (cobertura)",
}
JS_QUALITY = {
    "eslint": "ESLint", "prettier": "Prettier", "typescript": "TypeScript", "@biomejs/biome": "Biome",
    "snyk": "Snyk",
}
PY_HINTS = {
    "django": "Django", "flask": "Flask", "fastapi": "FastAPI", "sqlalchemy": "SQLAlchemy",
    "pytest": "pytest", "requests": "requests", "celery": "Celery", "pydantic": "Pydantic",
}

CLI_TOOLS = {
    # nome: (comando de versão, verificações que habilita)
    "node": (["node", "--version"], []),
    "npm": (["npm", "--version"], ["deps"]),
    "eslint": (["eslint", "--version"], ["lint"]),
    "prettier": (["prettier", "--version"], ["format"]),
    "tsc": (["tsc", "--version"], ["types"]),
    "jest": (["jest", "--version"], ["tests"]),
    "vitest": (["vitest", "--version"], ["tests"]),
    "mocha": (["mocha", "--version"], ["tests"]),
    "cypress": (["cypress", "--version"], ["e2e"]),
    "playwright": (["playwright", "--version"], ["e2e"]),
    "semgrep": (["semgrep", "--version"], ["sast"]),
    "codeql": (["codeql", "version", "--format=terse"], ["sast"]),
    "snyk": (["snyk", "--version"], ["deps", "sast"]),
    "sonar-scanner": (["sonar-scanner", "--version"], ["sast", "maintainability"]),
    "python3": (["python3", "--version"], []),
    "pytest": (["pytest", "--version"], ["tests"]),
    "bandit": (["bandit", "--version"], ["sast"]),
    "pip-audit": (["pip-audit", "--version"], ["deps"]),
    "ruff": (["ruff", "--version"], ["lint"]),
    "mypy": (["mypy", "--version"], ["types"]),
    "gitleaks": (["gitleaks", "version"], ["secrets"]),
    "trufflehog": (["trufflehog", "--version"], ["secrets"]),
    "go": (["go", "version"], []),
    "govulncheck": (["govulncheck", "-version"], ["deps"]),
    "cargo": (["cargo", "--version"], []),
}


def detect(project: Path) -> dict:
    langs: Counter = Counter()
    test_files: list[str] = []
    configs: list[str] = []
    total_lines = 0
    config_names = {
        "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "tsconfig.json",
        ".eslintrc", ".eslintrc.js", ".eslintrc.cjs", ".eslintrc.json", ".eslintrc.yml", "eslint.config.js",
        "eslint.config.mjs", "eslint.config.cjs", "eslint.config.ts", ".prettierrc", "prettier.config.js",
        "jest.config.js", "jest.config.ts", "jest.config.cjs", "vitest.config.ts", "vitest.config.js",
        "vite.config.ts", "vite.config.js", ".mocharc.json", ".mocharc.js", ".mocharc.yml", "cypress.config.ts",
        "cypress.config.js", "playwright.config.ts", "playwright.config.js", "sonar-project.properties",
        ".semgrep.yml", ".semgrepignore", "requirements.txt", "requirements-dev.txt", "pyproject.toml",
        "setup.py", "setup.cfg", "Pipfile", "poetry.lock", "pytest.ini", "tox.ini", "go.mod", "Cargo.toml",
        "pom.xml", "build.gradle", "Gemfile", "composer.json", "Dockerfile", "docker-compose.yml",
        ".env", ".env.local", ".env.production", ".gitignore", ".snyk", "biome.json",
    }
    for p in iter_files(project):
        r = rel(project, p)
        ext = p.suffix.lower()
        if p.name in config_names or r.startswith(".github/workflows/"):
            configs.append(r)
        lang = SOURCE_EXT.get(ext)
        if lang:
            langs[lang] += 1
            try:
                with p.open("rb") as fh:
                    total_lines += sum(1 for _ in fh)
            except OSError:
                pass
            if is_test_file(r):
                test_files.append(r)

    pkg = load_json(project / "package.json", {}) or {}
    deps = {**pkg.get("dependencies", {}), **pkg.get("peerDependencies", {})}
    dev = pkg.get("devDependencies", {}) or {}
    all_js = {**deps, **dev}
    py_reqs = ""
    for f in ("requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "setup.py"):
        fp = project / f
        if fp.exists():
            py_reqs += (fp.read_text(encoding="utf-8", errors="replace").lower() + "\n")

    frameworks = sorted({v for k, v in JS_FRAMEWORKS.items() if k in all_js} |
                        {v for k, v in PY_HINTS.items() if k in py_reqs and v != "pytest"})
    test_tools = sorted({v for k, v in JS_TEST_TOOLS.items() if k in all_js} |
                        ({"pytest"} if "pytest" in py_reqs or (project / "pytest.ini").exists() else set()))
    scripts = pkg.get("scripts", {}) or {}
    if "node --test" in json.dumps(scripts):
        test_tools.append("node:test (nativo)")
    quality = sorted({v for k, v in JS_QUALITY.items() if k in all_js})

    tools = {}
    for name, (cmd, checks) in CLI_TOOLS.items():
        path = which(cmd[0], project)
        info = {"available": bool(path), "path": path, "enables": checks, "version": None}
        if path:
            info["version"] = tool_version([path] + cmd[1:], project)
        tools[name] = info

    return {
        "generated_at": now_iso(),
        "project": project.resolve().name,
        "project_path": str(project.resolve()),
        "languages": dict(langs.most_common()),
        "source_lines": total_lines,
        "frameworks": frameworks,
        "test_tools_declared": sorted(set(test_tools)),
        "quality_tools_declared": quality,
        "package_json": bool(pkg),
        "package_scripts": scripts,
        "node_modules_installed": (project / "node_modules").is_dir(),
        "lockfiles": [f for f in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                                  "poetry.lock", "Pipfile.lock", "go.sum", "Cargo.lock") if (project / f).exists()],
        "config_files": sorted(configs),
        "test_files": sorted(test_files),
        "test_file_count": len(test_files),
        "is_typescript": langs.get("ts", 0) > 0 or (project / "tsconfig.json").exists(),
        "has_python": langs.get("py", 0) > 0,
        "has_ci": any(c.startswith(".github/workflows/") for c in configs),
        "tools": tools,
        "recommended_tools": recommend(langs, all_js, py_reqs, frameworks),
    }


def recommend(langs: Counter, js: dict, py: str, frameworks: list[str]) -> list[dict]:
    """Seleciona ferramentas adequadas a stack (não 'todas indiscriminadamente')."""
    rec = []
    is_js = langs.get("js", 0) + langs.get("ts", 0) > 0 or bool(js)
    is_ui = any(f in frameworks for f in ("React", "Vue", "Angular", "Svelte", "Next.js", "Nuxt"))
    is_api = any(f in frameworks for f in ("Express", "Fastify", "Koa", "NestJS", "hapi", "Flask", "FastAPI", "Django"))
    if is_js:
        uses_vite = "vite" in js or "vitest" in js
        rec.append({"tool": "Vitest" if uses_vite else "Jest", "why": "testes unitarios/integração"
                    + (" (projeto ja usa Vite)" if uses_vite else "")})
        rec.append({"tool": "ESLint", "why": "análise estática e regras de qualidade"})
        rec.append({"tool": "Prettier", "why": "formatação consistente"})
        rec.append({"tool": "npm audit", "why": "dependências vulneráveis"})
        if langs.get("ts", 0):
            rec.append({"tool": "TypeScript Compiler (tsc --noEmit)", "why": "erros de tipo"})
        if is_ui:
            rec.append({"tool": "Testing Library", "why": "testes de componentes"})
            rec.append({"tool": "Playwright", "why": "fluxos E2E de navegação"})
        if is_api:
            rec.append({"tool": "Supertest", "why": "testes de rotas HTTP"})
    if langs.get("py", 0):
        rec += [{"tool": "pytest (+pytest-cov)", "why": "testes e cobertura"},
                {"tool": "ruff", "why": "lint rápido"},
                {"tool": "bandit", "why": "SAST específico de Python"},
                {"tool": "pip-audit", "why": "dependências vulneráveis"}]
    rec.append({"tool": "Semgrep (p/owasp-top-ten)", "why": "SAST multi-linguagem alinhado ao OWASP Top 10"})
    rec.append({"tool": "CodeQL", "why": "SAST profundo (melhor no CI via GitHub Actions)"})
    rec.append({"tool": "Varredura de segredos (scan_secrets.py / gitleaks)", "why": "credenciais expostas"})
    return rec


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--out")
    a = ap.parse_args()
    project = Path(a.project)
    if not project.is_dir():
        sys.exit(f"projeto não encontrado: {project}")
    d = out_dir(project, a.out)
    stack = detect(project)
    write_json(d / "stack.json", stack)
    avail = [k for k, v in stack["tools"].items() if v["available"]]
    print(f"[detect] linguagens: {stack['languages']}")
    print(f"[detect] frameworks: {stack['frameworks'] or '-'} | testes declarados: {stack['test_tools_declared'] or '-'}")
    print(f"[detect] arquivos de teste: {stack['test_file_count']} | ferramentas disponíveis: {', '.join(avail) or '-'}")
    print(f"[detect] -> {d / 'stack.json'}")


if __name__ == "__main__":
    main()
