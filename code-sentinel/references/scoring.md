# CODE INTEGRITY SCORE (CIS) — Metodologia

Implementação: `scripts/cis_score.py`. Este documento explica cada regra para que você possa
justificar a nota ao usuário — e para que ninguém (nem você) consiga "maquiar" o resultado.

## Sumário
1. Princípios
2. Pesos dos critérios
3. Confiança (o que foi verificado)
4. Saúde (o que foi encontrado)
5. Critério de testes
6. Tetos (gates)
7. Níveis e cadeados
8. Prontidão (Desenvolvimento → Produção)
9. Triagem manual e efeito na nota
10. Exemplos de cálculo

## 1. Princípios

- **Evidência antes de nota.** Um critério só pontua na proporção das verificações efetivamente
  executadas. Não encontrar erro sem ter procurado vale zero.
- **Gravidade domina média.** Uma vulnerabilidade crítica não é compensada por boa manutenibilidade:
  tetos limitam a nota final independentemente da soma.
- **Status importa.** Achado confirmado pesa mais que risco potencial, que pesa mais que hipótese.
- **Transparência.** `score.json` traz pontos, confiança, saúde, penalidades por regra e tetos aplicados.

## 2. Pesos dos critérios

| Critério | Peso | Categoria (`category`) |
|---|---|---|
| Testes automatizados | 20 | `tests` |
| Segurança e vulnerabilidades | 25 | `security` |
| Integridade e lógica | 20 | `integrity` |
| Estabilidade e tratamento de erros | 15 | `stability` |
| Performance | 10 | `performance` |
| Manutenibilidade | 10 | `maintainability` |

`pontos(critério) = peso × confiança × saúde` (exceto Testes, seção 5).

## 3. Confiança

Cada critério tem verificações com pesos internos (somam 1). Verificações "não aplicáveis"
(ex.: `types` em projeto JS puro, `deps` sem manifesto) são removidas e os pesos redistribuídos.

| Critério | Verificações (peso) |
|---|---|
| Segurança | `deps` 0.25 · `secrets` 0.15 · `sast` 0.20 · `sast_heuristic` 0.15 · `manual_security_review` 0.25 |
| Integridade | `syntax` 0.20 · `types` 0.15 · `lint` 0.15 · `tests_executed` 0.25 · `manual_logic_review` 0.25 |
| Estabilidade | `error_handling_heuristic` 0.25 · `edge_case_tests` 0.35 · `tests_executed` 0.15 · `manual_error_review` 0.25 |
| Performance | `perf_heuristic` 0.35 · `perf_tests` 0.30 · `manual_perf_review` 0.35 |
| Manutenibilidade | `lint` 0.30 · `duplication` 0.25 · `complexity_heuristic` 0.20 · `format` 0.05 · `manual_arch_review` 0.20 |

De onde vem cada verificação:
- `scan_secrets.py` → `secrets`; `scan_patterns.py` → `sast_heuristic`, `error_handling_heuristic`,
  `perf_heuristic`, `duplication`, `complexity_heuristic`.
- `run_tools.py` → `syntax` (node --check / ast.parse), `types` (tsc), `lint` (ESLint/ruff),
  `format` (Prettier), `deps` (npm audit/pip-audit), `sast` (Semgrep/bandit), `tests_executed`,
  `coverage`, `edge_case_tests` (testes executados + ≥3 categorias de borda nos arquivos de teste).
- `evidence/manual.json` → `manual_*`, `perf_tests`, `edge_case_tests` e qualquer verificação feita
  com ferramenta externa (ex.: `"sast"` se você rodou CodeQL e registrou os achados).

A **confiança geral** é a média ponderada das confianças (Testes conta como 1.0 se cobertura medida,
0.7 se não, 0.2 se testes existem mas não rodaram): Alta ≥ 75%, Média ≥ 45%, Baixa abaixo.

## 4. Saúde

`saúde = max(0, 1 − Σ penalidades)` dos achados da categoria.

| Gravidade | Penalidade base | × Status | Fator |
|---|---|---|---|
| CRÍTICO | 0.60 | confirmado | 1.0 |
| ALTO | 0.30 | risco potencial | 0.5 |
| MÉDIO | 0.12 | hipótese | 0.2 |
| BAIXO | 0.04 | | |
| INFORMATIVO | 0.00 | | |

Repetições da mesma regra têm retorno decrescente (1×, ½×, ¼× … até 6 ocorrências), para que
50 ocorrências do mesmo padrão não pesem 50 vezes, mas também não pesem como uma só.

Achados duplicados entre ferramentas (mesmo arquivo, linha e categoria) são unidos: fica a maior
gravidade e o status mais forte; `also_reported_by` lista as outras fontes.

## 5. Critério de testes (20)

| Situação | Pontos |
|---|---|
| Nenhum arquivo de teste | 0 |
| Testes existem mas não foram executados | 3 (máx.) |
| Executados | `8 × taxa_de_aprovação` + cobertura + bordas |

- Cobertura: `10 × min(1, cobertura_efetiva / 80)`; se não medida, 2 pontos.
- **Cobertura efetiva**: runners medem só arquivos carregados pelos testes. `run_tools.py` recalcula
  sobre todo o código-fonte da linguagem, contando arquivos nunca importados como 0% (o valor do
  runner fica em `lines_reported`). Isso evita "100% de cobertura" com 1 arquivo testado em 10.
- Bordas: 2 pontos com ≥3 categorias (vazio/nulo, entrada inválida, limites, concorrência, falha
  externa, auth/permissão, duplicados) nos testes; 1 ponto com 1–2.
- Testes falhando já reduzem a taxa de aprovação (não são penalizados duas vezes), mas geram teto.

## 6. Tetos (gates)

Aplicados depois da soma; vale o menor.

| Condição | Teto | Efeito |
|---|---|---|
| CRÍTICO **confirmado** (qualquer categoria) | 59 | no máximo Nível 2; se de segurança, critério Segurança ≤ 5/25 |
| CRÍTICO potencial/hipótese não descartado | 74 | no máximo Nível 3 |
| ALTO de segurança confirmado | 74 | no máximo Nível 3 |
| ALTO em aberto (seg. potencial ou qualquer confirmado) | 89 | sem Nível 5 |
| Testes inexistentes ou não executados | 74 | sem Nível 4 ("boa cobertura" não comprovada) |
| Testes falhando | 74 | |
| Cobertura efetiva < 60% | 74 | |
| Cobertura efetiva < 80% ou não medida | 89 | Nível 5 exige ≥ 80% |
| Confiança de segurança < 50% | 74 | não se pode afirmar segurança sem verificar |
| Sem `deps` + `secrets` + (`sast` ou revisão manual de segurança) | 89 | |
| Lint (ESLint/ruff...) não executado | 89 | Nível 5 exige análise estática de qualidade |

## 7. Níveis e cadeados

| Nível | Faixa | Nome | Imagem |
|---|---|---|---|
| 1 | 0–39 | Código Exposto | `assets/padlocks/level-1.(svg|png)` — cadeado aberto, rachado, alerta |
| 2 | 40–59 | Proteção Fraca | `level-2` — arco levantado, ainda destravado |
| 3 | 60–74 | Proteção Moderada | `level-3` — fechado, simples |
| 4 | 75–89 | Alta Integridade | `level-4` — reforçado, escudo, rebites |
| 5 | 90–100 | Integridade Máxima | `level-5` — premium dourado, núcleo ciano, hexágono com check |

Os 5 "pips" sob cada cadeado indicam o nível. SVGs são a fonte; PNGs são renderizados com
`node scripts/render_padlocks.js` (Playwright). Regerar SVGs: `python3 scripts/make_padlocks.py`.

## 8. Prontidão

A aprovação depende de critérios, não só da nota:

| Etapa | Exige |
|---|---|
| Desenvolvimento | sempre apto (ressalva se houver erro de compilação) |
| Testes (QA) | sem erros de sintaxe/compilação |
| Homologação | sem CRÍTICO confirmado, testes executados e verdes, CIS ≥ 60 (ressalva se houver CRÍTICO potencial) |
| Produção | nenhum CRÍTICO (qualquer status), nenhum ALTO de segurança, nenhum ALTO confirmado, testes verdes, cobertura efetiva ≥ 70%, `deps` + `secrets` + (`sast` ou revisão manual), CIS ≥ 75 |

## 9. Triagem manual

Em `findings/manual.json` (formato em `finding-schema.md`):
- `status: "false_positive" | "fixed" | "accepted_risk"` + mesmo `file`/`line` (+ `category` ou
  `target_rule_id`) remove o achado correspondente da nota; ele aparece em
  `findings_resolved_by_triage` com a justificativa. `accepted_risk` exige decisão do usuário.
- `"override": true` substitui o achado correspondente (para rebaixar/elevar gravidade ou mudar status
  com justificativa).
- Achados novos (sem `override`) somam normalmente.

## 10. Exemplos (projetos de teste em `tests/fixtures/`)

**vulnerable-shop** (falhas intencionais), com `--run-tests`, sem revisão manual:
4 críticos confirmados (chaves AWS/Stripe, erro de sintaxe, minimist vulnerável) → teto 59;
2 testes falhando e cobertura efetiva ~12% → teto 74; soma bruta ≈ 22 → **CIS ≈ 22, Nível 1**.

**healthy-lib** (bem testada), com `--run-tests`, sem revisão manual nem SAST dedicado:
testes 20/20; segurança 13.8/25 (confiança 55%); performance 3.5/10 (só heurística) → **CIS ≈ 64,
Nível 3**. Com npm audit + Semgrep executados → ≈ 69. Com a revisão manual declarada, a confiança sobe
e a soma bruta chega a 90 — mas o teto de lint (projeto sem ESLint) segura em **89, Nível 4**: a nota
subiu porque houve mais verificação, e o que falta para o Nível 5 fica explícito.
