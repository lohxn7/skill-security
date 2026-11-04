# Classificação de gravidade, probabilidade e status

## Gravidade

| Nível | Definição | Exemplos típicos |
|---|---|---|
| **CRÍTICO** | Pode comprometer completamente o sistema, permitir invasão ou causar perda de dados | SQL/command injection alcançável, RCE (eval/desserialização de entrada externa), credencial de produção/nuvem no código, bypass de autenticação, código que não compila no caminho principal, dependência com CVE crítico alcançável |
| **ALTO** | Pode provocar falhas graves ou comprometer funcionalidades importantes | Falta de autorização (IDOR, rota admin aberta), XSS armazenado/refletido, path traversal, TLS desativado, testes falhando, dependência não declarada, race condition em pagamento/estoque |
| **MÉDIO** | Comportamento inesperado em determinadas condições | JSON.parse sem try em entrada externa, catch vazio, divisão por zero em caso de borda, hash fraco, CORS `*`, falta de rate limit, vazamento de memória lento |
| **BAIXO** | Problemas menores, melhorias e otimizações | I/O síncrono fora do caminho quente, `parseInt` sem radix, duplicação, arquivos grandes |
| **INFORMATIVO** | Observação técnica sem risco imediato | TODO/FIXME, sugestão de ferramenta, formatação |

Ajuste pelo contexto, sempre justificando:
- **Eleve** quando o código está exposto à internet, trata dinheiro/dados pessoais/saúde, ou roda com privilégio.
- **Rebaixe** quando o código só roda em script local, teste, ferramenta interna sem entrada externa,
  ou quando há mitigação comprovada em outra camada (cite onde).
- Código de teste/fixtures: scanners já rebaixam automaticamente (segredo em teste ainda vaza, mas
  raramente é credencial real).

## Probabilidade de ocorrência

| Valor | Quando usar |
|---|---|
| `alta` / `certa` | Caminho comum, entrada externa direta, ou já reproduzido |
| `media` | Exige condição específica plausível (lista vazia, timeout, concorrência) |
| `baixa` | Exige combinação improvável ou acesso privilegiado prévio |
| `desconhecida` | Não há como estimar sem dados de uso — diga isso em vez de chutar |

## Status (confirmado × potencial × hipótese)

| Status | Critério objetivo |
|---|---|
| `confirmed` | Reproduzido por teste, apontado por ferramenta determinística (compilador, npm audit, teste falhando), ou leitura inequívoca (segredo literal, rota sem nenhum middleware em app sem proteção global) |
| `potential` | Padrão de risco real encontrado, mas exploração/ocorrência não comprovada (ex.: concatenação em SQL sem confirmar que o valor vem do usuário) |
| `hypothesis` | Suspeita que depende de contexto não disponível (config de produção, comportamento de serviço externo, carga real) |

Nunca apresente `potential`/`hypothesis` como fato. No relatório, a coluna "Classificação" deixa isso
explícito; na conversa, use "pode", "há risco de", "não confirmado".
