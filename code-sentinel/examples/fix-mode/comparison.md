# CODE SENTINEL — Comparação antes × depois

| Métrica | Antes (antes) | Depois (atual) | Δ |
|---|---|---|---|
| CODE INTEGRITY SCORE | 22 | 33 | +11 |
| Nível | 1 — Código Exposto | 1 — Código Exposto | +0 |
| Total de achados | 50 | 40 | -10 |
| CRÍTICO | 10 | 6 | -4 |
| ALTO | 14 | 12 | -2 |
| MÉDIO | 15 | 13 | -2 |
| BAIXO | 11 | 9 | -2 |
| INFORMATIVO | 0 | 0 | +0 |
| Testes (passaram/total) | 4/6 | 6/6 | |

## Resolvidos (10)

- [CRÍTICO] Erro de sintaxe (arquivo não compila) — `src/broken.js:2`
- [CRÍTICO] Entrada da requisição chega a uma consulta SQL montada dinamicamente (SQL Injection). — `src/server.js:19`
- [CRÍTICO] Entrada da requisição chega a um comando de shell (Command Injection / RCE). — `src/server.js:26`
- [CRÍTICO] Entrada da requisição é avaliada como código (eval/new Function) — execução remota de código. — `src/server.js:49`
- [ALTO] Teste falhando: media de avaliacoes com lista vazia retorna 0 — `test/pricing.test.js:1`
- [ALTO] Teste falhando: desconto invalido (acima de 100%) deve lancar erro — `test/pricing.test.js:1`
- [MÉDIO] Divisão por 'ratings.length' sem verificar zero — `src/pricing.js:5`
- [MÉDIO] Detalhes internos de erro expostos ao cliente — `src/server.js:20`
- [BAIXO] parseInt sem base (radix) e sem validação de NaN — `src/pricing.js:13`
- [BAIXO] SELECT * em consulta — `src/server.js:19`

## Novos / regressões (0)

- nenhum
