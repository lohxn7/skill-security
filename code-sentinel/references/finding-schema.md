# Formato de achados e evidências

Todos os scanners gravam no mesmo formato. Para registrar o que você encontrou na revisão manual,
crie/edite `<projeto>/.code-sentinel/findings/manual.json` e `<projeto>/.code-sentinel/evidence/manual.json`
e depois rode `sentinel.py rescore <projeto>`.

## findings/manual.json

```json
{
  "source": "manual",
  "findings": [
    {
      "rule_id": "MANUAL-IDOR-ORDERS",
      "title": "IDOR: qualquer usuário autenticado lê pedidos de outros",
      "severity": "HIGH",
      "status": "confirmed",
      "category": "security",
      "file": "src/routes/orders.js",
      "line": 42,
      "description": "GET /orders/:id busca por id sem filtrar por req.user.id.",
      "failure_mode": "Usuário A enumera ids e lê pedidos (endereço, CPF) de qualquer cliente.",
      "likelihood": "alta",
      "impact": "Vazamento de dados pessoais (LGPD), fraude.",
      "fix": "Filtrar por dono e retornar 404 quando não pertencer ao usuário.",
      "fixed_code": "const order = await Order.findOne({ id: req.params.id, userId: req.user.id });\nif (!order) return res.sendStatus(404);",
      "evidence": "Teste .code-sentinel/generated-tests/orders-idor.test.js falha: 200 com pedido de outro usuário.",
      "cwe": "CWE-639",
      "owasp": "A01:2021 Broken Access Control / ASVS V4.2.1"
    }
  ]
}
```

### Campos

| Campo | Obrigatório | Valores / observação |
|---|---|---|
| `title` | sim | Nome do problema (item 1 do relatório) |
| `file`, `line` | sim | Localização exata (item 2). Use `end_line` para intervalos |
| `description` | sim | O que está acontecendo (item 3) |
| `failure_mode` | sim | Como pode quebrar o sistema (item 4) |
| `severity` | sim | `CRITICAL` `HIGH` `MEDIUM` `LOW` `INFO` (item 5) — critérios em `severity-guide.md` |
| `likelihood` | recomendado | `alta` `media` `baixa` `desconhecida` (item 6) |
| `impact` | recomendado | Impacto potencial (item 7) |
| `fix` | sim | Sugestão de correção (item 8) |
| `fixed_code` | quando aplicável | Código corrigido ou exemplo (item 9) |
| `status` | sim | `confirmed` `potential` `hypothesis` (achado) · `false_positive` `fixed` `accepted_risk` (triagem) |
| `category` | sim | `tests` `security` `integrity` `stability` `performance` `maintainability` |
| `rule_id` | recomendado | Identificador estável (agrupa repetições) |
| `evidence` | recomendado | Saída de teste/ferramenta/trecho. **Mascare segredos** |
| `cwe`, `owasp` | quando aplicável | Referências |
| `override` | triagem | `true` substitui achado(s) no mesmo `file`/`line`/`category` |
| `target_rule_id` | triagem | Restringe a triagem a um `rule_id` específico (ex.: `npm-audit:lodash`) |
| `justification` | triagem | Obrigatória para `false_positive`, `accepted_risk` e `override` |

### Exemplos de triagem

Falso positivo (rota protegida por middleware global):
```json
{"title": "Rota admin protegida por app.use(requireAdmin)", "file": "src/server.js", "line": 29,
 "category": "security", "status": "false_positive", "target_rule_id": "JS-ADMIN-ROUTE-NO-AUTH",
 "justification": "src/server.js:12 aplica app.use('/admin', requireAuth, requireRole('admin')) antes das rotas."}
```

Promover a confirmado após teste reproduzir:
```json
{"title": "Média de avaliações retorna NaN para produto sem avaliações", "file": "src/pricing.js", "line": 5,
 "category": "integrity", "severity": "HIGH", "status": "confirmed", "override": true,
 "description": "calculateAverageRating([]) => NaN", "failure_mode": "API responde {average: null}; UI quebra.",
 "fix": "Retornar 0 (ou null explícito) para lista vazia.", "evidence": "test/pricing.test.js: 'lista vazia retorna 0' falha",
 "justification": "Reproduzido pela suíte do projeto."}
```

## evidence/manual.json

```json
{
  "checks": ["manual_security_review", "manual_logic_review", "manual_error_review"],
  "not_applicable": [],
  "scope": "src/routes, src/services/payment.js (linha a linha); restante por amostragem",
  "summary": "Resumo executivo de 3–5 frases exibido no topo do relatório.",
  "external_tools": [{"tool": "CodeQL", "version": "2.19.1", "result": "3 alertas importados em findings/manual.json"}]
}
```

Verificações aceitas em `checks`: `manual_security_review`, `manual_logic_review`,
`manual_error_review`, `manual_perf_review`, `manual_arch_review`, `perf_tests`, `edge_case_tests`,
e — quando você executou uma ferramenta fora do `run_tools.py` e importou os resultados — `sast`,
`deps`, `lint`, `types`, `format`. Declare apenas o que foi realmente feito.
