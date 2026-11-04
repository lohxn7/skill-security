# CODE SENTINEL — Skill de auditoria e integridade de código para Claude

<p align="center"><img src="code-sentinel/examples/padlocks-preview.png" alt="Os cinco níveis de cadeado do CODE SENTINEL" width="900"></p>

O **CODE SENTINEL** faz o Claude atuar como um engenheiro sênior de QA/AppSec: audita o projeto,
executa as ferramentas adequadas à stack, roda a suíte de testes com cobertura, procura onde o código
**pode** quebrar, atribui o **CODE INTEGRITY SCORE (0–100)** com um cadeado de 5 níveis e gera um
relatório profissional (Markdown + HTML). Também tem modo de correção com comparação antes × depois.

| Nível | Faixa | Nome |
|---|---|---|
| 1 | 0–39 | Código Exposto |
| 2 | 40–59 | Proteção Fraca |
| 3 | 60–74 | Proteção Moderada |
| 4 | 75–89 | Alta Integridade |
| 5 | 90–100 | Integridade Máxima |

## Estrutura

```
code-sentinel/
├── SKILL.md                     # instruções da skill (fluxo, regras, modo de correção)
├── scripts/
│   ├── sentinel.py              # orquestrador: audit | rescore | snapshot | compare
│   ├── detect_stack.py          # linguagens, frameworks, ferramentas instaladas e versões
│   ├── scan_secrets.py          # credenciais expostas (sempre mascaradas) + .env versionado
│   ├── scan_patterns.py         # SAST heurístico JS/TS/Python, erros, performance, duplicação
│   ├── run_tools.py             # sintaxe, tsc, ESLint, Prettier, npm audit, pip-audit, Semgrep,
│   │                            # bandit, ruff, testes (Jest/Vitest/Mocha/node:test/pytest) + cobertura
│   ├── cis_score.py             # CODE INTEGRITY SCORE, tetos, confiança, prontidão
│   ├── render_report.py         # relatório Markdown + HTML autocontido com o cadeado
│   ├── common.py                # utilitários e formato de achados
│   ├── make_padlocks.py         # gera os 5 cadeados SVG
│   └── render_padlocks.js       # renderiza os PNG transparentes (Playwright)
├── assets/
│   ├── padlocks/level-{1..5}.svg|png
│   └── semgrep/sentinel-rules.yml   # regras Semgrep (taint) que funcionam offline
├── references/                  # metodologia e guias carregados sob demanda
│   ├── scoring.md  finding-schema.md  severity-guide.md  audit-checklist.md
│   └── tool-matrix.md  stress-testing.md  fix-mode.md
├── examples/                    # relatórios REAIS gerados pela skill
│   ├── vulnerable-shop/   (25/100 · Nível 1)   healthy-lib/ (89/100 · Nível 4)
│   └── fix-mode/comparison.md   padlocks-preview.png
├── tests/
│   ├── test_sentinel.py         # 22 testes da própria skill
│   └── fixtures/vulnerable-shop # projeto com falhas intencionais (Node + Python)
│       fixtures/healthy-lib     # projeto saudável (controle)
└── evals/                       # casos no formato `claude plugin eval`
```

## Instalação

Requisitos: Python ≥ 3.9 (só biblioteca padrão). Node.js para projetos JS. As ferramentas externas são
**opcionais** — o que não estiver instalado é reportado e reduz a confiança da nota, nunca é inventado.

**Claude Code** (pessoal, todos os projetos):
```bash
git clone https://github.com/lohxn7/skill-security.git
mkdir -p ~/.claude/skills && cp -r skill-security/code-sentinel ~/.claude/skills/
```
Ou por projeto: copie para `<seu-projeto>/.claude/skills/code-sentinel`.

**Claude.ai / app** (Settings → Capabilities → Skills): envie o arquivo `code-sentinel.skill`
(zip da pasta; gere com `cd code-sentinel/.. && zip -r code-sentinel.skill code-sentinel -x '*/evals/*'`).

Ferramentas recomendadas (opcionais): `pip install semgrep bandit pip-audit ruff`; no projeto JS,
ESLint/Prettier/TypeScript e o test runner já usados por ele.

## Primeira auditoria

No Claude, basta pedir — a skill é acionada por pedidos como:

> "Audite o projeto em ./api e me dê a nota de integridade. Pode rodar os testes."

> "Esse código está pronto para produção?" · "Ative o modo de correção e suba a nota."

Ou rode os scripts diretamente:
```bash
python3 code-sentinel/scripts/sentinel.py audit ./meu-projeto --run-tests
# → ./meu-projeto/.code-sentinel/report.md, report.html, score.json, padlock-level-N.png
```
`--run-tests` executa a suíte do projeto (código do projeto): use apenas quando ela não aponta para
serviços reais. Modo de correção:
```bash
python3 code-sentinel/scripts/sentinel.py snapshot ./meu-projeto antes
# ... correções aprovadas ...
python3 code-sentinel/scripts/sentinel.py audit ./meu-projeto --run-tests
python3 code-sentinel/scripts/sentinel.py compare ./meu-projeto antes   # → comparison.md
```

## Validação

```bash
cd code-sentinel && python3 -m unittest discover -s tests -v
```
Os testes verificam: detecção de todas as falhas plantadas no `vulnerable-shop` (23 regras), segredos
nunca vazam no relatório, heurística nunca marcada como confirmada, tetos de nota (crítico ≤ 59,
testes falhando ≤ 74, ausência de verificação não pontua), triagem de falso positivo, cobertura efetiva,
relatórios com cadeado, auditoria não escreve no projeto auditado, snapshot/compare.

Resultados nos fixtures: **vulnerable-shop 22–25/100 (Nível 1)** — 10 críticos (RCE via eval/exec
comprovada por fluxo de dados, SQL injection, chave AWS e credenciais hardcoded, módulo que não compila, minimist com
CVE crítico), 2 testes falhando e cobertura efetiva de 12% (o runner reportava 100%); **healthy-lib
89/100 (Nível 4)**, limitada ao 4 porque o projeto não tem lint configurado. No modo de correção, o
vulnerable-shop foi de 22 → 33 com 10 problemas resolvidos e 0 regressões.

## Limitações conhecidas

- O scanner próprio (`scan_patterns.py`) é heurístico (regex + contexto local) e cobre JS/TS e Python;
  por isso marca tudo como "risco potencial". Confirmação vem de Semgrep (taint), testes ou revisão.
- Outras linguagens: segredos e a revisão do Claude funcionam; ferramentas específicas (govulncheck,
  SpotBugs, Brakeman...) são orientadas por `references/tool-matrix.md` e registradas manualmente.
- `npm audit`, `pip-audit` e o ruleset do registry do Semgrep exigem rede. Sem rede, o Semgrep usa o
  ruleset local empacotado; os demais ficam como "falhou" com o motivo, e a nota reflete isso.
- Cobertura efetiva é estimada por linhas não vazias dos arquivos nunca carregados (aproximação).
- Projetos yarn/pnpm: auditoria de dependências não é automática (instruções no relatório).
- ESLint só roda se o projeto já tiver configuração; a skill não cria configs sem autorização.
- Testes E2E (Cypress/Playwright) não são executados automaticamente: exigem app rodando em
  ambiente de teste e autorização.
- A nota mede integridade **verificada**; não substitui pentest nem revisão de arquitetura por humanos.
