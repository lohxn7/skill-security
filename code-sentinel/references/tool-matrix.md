# Matriz de ferramentas — quando usar, como rodar, como configurar

Regra: escolha pela stack detectada (`stack.json` → `recommended_tools`), não use todas. Se uma
ferramenta útil não estiver instalada, **informe e ofereça** instalar/configurar; só execute
instalação ou crie arquivos de configuração com autorização explícita. Registre o que rodar fora do
`run_tools.py` em `evidence/manual.json` → `external_tools` e os achados em `findings/manual.json`.

## Sumário
1. Seleção rápida por stack
2. Testes (Jest, Vitest, Mocha/Chai, Testing Library, Cypress, Playwright, Supertest, node:test, pytest)
3. Análise estática (ESLint, Prettier, tsc, SonarQube, CodeQL, Semgrep)
4. Segurança de dependências e segredos (npm audit, Snyk, pip-audit, gitleaks)
5. Outras linguagens

## 1. Seleção rápida

| Stack | Testes | Estática | Segurança |
|---|---|---|---|
| Node/Express/Fastify API | Jest ou Vitest + Supertest | ESLint (+ eslint-plugin-security), tsc se TS | npm audit, Semgrep |
| React/Vue/Svelte + Vite | Vitest + Testing Library; Playwright para E2E | ESLint, tsc, Prettier | npm audit, Semgrep |
| Next.js | Jest/Vitest + Testing Library; Playwright | ESLint (next), tsc | npm audit, Semgrep, CodeQL |
| Lib JS sem deps | node:test ou Vitest | ESLint, tsc | Semgrep |
| Python (Flask/FastAPI/Django) | pytest + pytest-cov (+ httpx/TestClient) | ruff, mypy | bandit, pip-audit, Semgrep |
| Monorepo grande / CI GitHub | — | SonarQube | CodeQL (Actions), Snyk |

## 2. Testes

**Jest** — `npm i -D jest` · rodar: `npx jest --coverage` · cobertura de todos os arquivos:
`collectCoverageFrom: ['src/**/*.{js,ts}']` no `jest.config.js` (sem isso, só arquivos importados contam).

**Vitest** (projetos Vite/ESM) — `npm i -D vitest @vitest/coverage-v8` · `npx vitest run --coverage`
· `coverage: { all: true, include: ['src/**'] }`.

**Mocha + Chai** — `npm i -D mocha chai c8` · `npx c8 mocha` · BDD: `expect(x).to.equal(y)`.

**Testing Library** — `@testing-library/react|vue|dom` + `@testing-library/jest-dom`; teste
comportamento visível (`getByRole`), não implementação.

**Cypress** — E2E com app rodando em ambiente de teste: `npx cypress run`. Nunca aponte para produção.

**Playwright** — `npm i -D @playwright/test && npx playwright install` · `npx playwright test`.
Bom para fluxos críticos (login, checkout) e múltiplos navegadores.

**Supertest** — testes HTTP sem subir porta: exporte o `app` separado do `listen`.
```js
const request = require('supertest');
const app = require('../src/app');
test('GET /users exige auth', async () => {
  await request(app).get('/users').expect(401);
});
```

**node:test** (nativo, Node ≥ 18) — `node --test --experimental-test-coverage` (o `run_tools.py` usa).

**pytest** — `pip install pytest pytest-cov` · `pytest --cov=src --cov-report=term-missing`.

## 3. Análise estática

**ESLint** — sem config o `run_tools.py` pula (não inventa regras). Config mínima sugerida
(`eslint.config.js`, flat config, ESLint ≥ 9), criar só com autorização:
```js
const js = require('@eslint/js');
const security = require('eslint-plugin-security');
module.exports = [
  js.configs.recommended,
  security.configs.recommended,
  { languageOptions: { ecmaVersion: 2023, sourceType: 'commonjs', globals: { require: 'readonly', module: 'writable', process: 'readonly', __dirname: 'readonly', console: 'readonly' } },
    rules: { eqeqeq: 'error', 'no-unused-vars': 'warn', complexity: ['warn', 12], 'max-depth': ['warn', 4] } },
];
```
`npm i -D eslint @eslint/js eslint-plugin-security`.

**Prettier** — `npx prettier --check .` (só verificação; `--write` altera arquivos → autorização).

**TypeScript Compiler** — `npx tsc --noEmit -p tsconfig.json`. Recomende `"strict": true`.

**SonarQube** — exige servidor/token. `sonar-project.properties` + `sonar-scanner`. Útil para
histórico de dívida técnica; não é pré-requisito da auditoria.

**CodeQL** — melhor via GitHub Actions (`github/codeql-action`). Local:
`codeql database create db --language=javascript && codeql database analyze db --format=sarif-latest --output=codeql.sarif javascript-security-and-quality.qls`.
Importe os alertas para `findings/manual.json` (status `potential`, ou `confirmed` após verificar fluxo).

**Semgrep** — `pip install semgrep` · `semgrep scan --config p/owasp-top-ten --metrics=off` (o
`run_tools.py` usa esse ruleset; precisa de rede para baixar as regras; a primeira execução pode levar minutos). Outros rulesets:
`p/javascript`, `p/typescript`, `p/python`, `p/secrets`, `p/nodejsscan`.

## 4. Dependências e segredos

**npm audit** — precisa de `package-lock.json`. `npm audit --json`. `npm audit fix` **altera** o
lockfile → só com autorização; `--force` pode subir major e quebrar API.
yarn: `yarn npm audit --json` · pnpm: `pnpm audit --json`.

**Snyk** — `npm i -g snyk && snyk auth` (conta necessária) · `snyk test --json` (deps) ·
`snyk code test` (SAST).

**pip-audit** — `pip install pip-audit` · `pip-audit -r requirements.txt -f json`.

**Segredos** — `scan_secrets.py` (incluso) cobre os padrões mais comuns no código atual. Para o
**histórico git**: `gitleaks detect --source . --report-format json` ou `trufflehog git file://.`.
Segredo encontrado = considerar comprometido → rotacionar, não só apagar.

## 5. Outras linguagens

| Linguagem | Testes | Estática/SAST | Dependências |
|---|---|---|---|
| Go | `go test -race -cover ./...` | `go vet`, `staticcheck`, `gosec` | `govulncheck ./...` |
| Java/Kotlin | JUnit + JaCoCo | SpotBugs + FindSecBugs, PMD | OWASP Dependency-Check |
| C#/.NET | xUnit + coverlet | Roslyn analyzers, SecurityCodeScan | `dotnet list package --vulnerable` |
| PHP | PHPUnit | PHPStan/Psalm | `composer audit` |
| Ruby | RSpec + SimpleCov | RuboCop, Brakeman | `bundler-audit` |
| Rust | `cargo test`, `cargo tarpaulin` | `clippy` | `cargo audit` |
