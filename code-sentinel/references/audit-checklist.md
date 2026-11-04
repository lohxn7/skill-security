# Checklist de revisão manual

Use depois dos scanners. Eles acham padrões; você acha **intenção violada**. Priorize pelo risco:
entradas externas → autenticação/autorização → dados sensíveis → dinheiro/estado → resto.

## Sumário
1. Mapa rápido do sistema
2. OWASP Top 10 (2021) — o que procurar
3. OWASP ASVS — controles essenciais
4. Lógica e integridade
5. Integração entre módulos e dependências
6. Estabilidade e tratamento de erros
7. Performance e memória
8. Manutenibilidade e arquitetura

## 1. Mapa rápido (5 minutos que economizam horas)
- Pontos de entrada: rotas HTTP, handlers de fila, CLIs, cron jobs, webhooks, WebSockets.
- Fronteiras de confiança: o que vem do usuário, de terceiros, do banco, de variáveis de ambiente.
- Ativos: credenciais, dados pessoais (LGPD), pagamentos, permissões.
- Como roda: processo longo (vazamentos importam) ou serverless; single-instance ou cluster (estado em memória quebra).

## 2. OWASP Top 10 (2021)

| ID | Procure | Sinais no código |
|---|---|---|
| A01 Broken Access Control | IDOR, rota sem auth, checagem só no front, escalonamento de papel | `findById(req.params.id)` sem filtro por dono; `isAdmin` vindo do body; CORS permissivo com credenciais |
| A02 Cryptographic Failures | Hash rápido para senha, segredo fraco, TLS desligado, dados sensíveis sem criptografia | `md5`, `sha1`, `Math.random` para token, `rejectUnauthorized:false`, JWT HS256 com segredo curto |
| A03 Injection | SQL/NoSQL/OS/LDAP/template injection, XSS | concatenação em query, `$where`, `exec` com string, `innerHTML`, `res.send(req.query.x)` |
| A04 Insecure Design | Falta de limites de negócio | sem rate limit em login/OTP, sem idempotência em pagamento, sem limite de tamanho de upload |
| A05 Security Misconfiguration | Debug ligado, stack trace exposto, headers ausentes | `DEBUG=True`, `err.stack` na resposta, sem `helmet`, diretório listável |
| A06 Vulnerable Components | Dependências com CVE, abandonadas, não fixadas | resultado de `npm audit`/`pip-audit`; `*` ou `latest` em versões; sem lockfile |
| A07 Identification & Auth Failures | Sessão/JWT/senha | `jwt.decode` sem verify, sem expiração, senha sem política, sessão não invalidada no logout |
| A08 Software & Data Integrity | Desserialização, supply chain, updates sem assinatura | `pickle.loads`, `yaml.load`, `postinstall` suspeito, CI que executa código de PR com segredos |
| A09 Logging & Monitoring Failures | Sem log de eventos de segurança, log com dados sensíveis | `console.log(password)`, catch vazio, falha de login não registrada |
| A10 SSRF | URL controlada pelo usuário em requisição do servidor | `fetch(req.body.url)`, webhooks sem allowlist, acesso a `169.254.169.254` |

## 3. OWASP ASVS (nível 1–2) — controles essenciais
- **V2 Autenticação**: hash adaptativo (bcrypt/argon2), rate limit, MFA em ações críticas, sem credencial default.
- **V3 Sessão**: cookies `HttpOnly`+`Secure`+`SameSite`, rotação no login, expiração e logout efetivo.
- **V4 Controle de acesso**: negar por padrão, checagem no servidor em **toda** rota, por recurso (dono).
- **V5 Validação/sanitização**: schema na fronteira (zod/joi/pydantic), allowlist, encoding de saída por contexto.
- **V6 Criptografia**: algoritmos atuais, aleatoriedade criptográfica, chaves fora do código.
- **V7 Erros e logs**: mensagens genéricas ao cliente, log estruturado com correlação, sem PII.
- **V8 Proteção de dados**: minimização, dados sensíveis não cacheados/logados, retenção.
- **V10 Código malicioso / V14 Configuração**: dependências fixadas e auditadas, headers de segurança, build reprodutível.

## 4. Lógica e integridade
- Casos vazios/nulos/zero: listas vazias, divisão, `undefined` em cadeias de propriedades.
- Conversões: `parseInt`, datas/fuso horário, ponto flutuante em dinheiro (use centavos/decimal).
- Condições invertidas, `==` vs `===`, comparações de string vs número, off-by-one em paginação.
- Estado compartilhado: variáveis de módulo mutáveis, argumentos default mutáveis (Python).
- Assíncrono: `forEach(async)`, Promise sem `await`, `await` em loop onde deveria ser paralelo (ou vice-versa).
- Idempotência e duplicidade: reenvio de requisição, retry que cobra duas vezes, unique constraints.
- Concorrência: read-modify-write sem transação/lock (estoque, saldo, contador).

## 5. Integração entre módulos e dependências
- Contratos: formato de retorno consistente; erros propagados vs. engolidos; `null` vs exceção.
- Imports quebrados, dependências não declaradas (scanner detecta), versões incompatíveis (peer deps).
- Variáveis de ambiente obrigatórias validadas na inicialização (falhar cedo).
- Chamadas externas: timeout, retry com backoff, circuit breaker, tratamento de resposta parcial.
- Migrações e schema: código assume colunas que podem não existir; ordem de deploy.

## 6. Estabilidade e tratamento de erros
- Handler global de erros (Express `app.use((err, req, res, next) => …)`), `unhandledRejection`.
- `try/catch` em parse de entrada externa; validação antes do uso.
- Recursos liberados em `finally` (conexões, arquivos, locks).
- Shutdown gracioso (SIGTERM), timers com `clearInterval`/`unref`.

## 7. Performance e memória
- N+1 consultas (loop com query), falta de índice em filtros frequentes, `SELECT *` em tabelas largas.
- Caches/maps/arrays de módulo sem limite (scanner detecta parte), listeners acumulando (`on` sem `off`).
- I/O síncrono em caminho de requisição, JSON gigante em memória (use streams), regex catastrófica (ReDoS).
- Paginação ausente em endpoints de listagem.

## 8. Manutenibilidade e arquitetura
- Funções > 50–80 linhas, aninhamento > 4 níveis, arquivos > 500 linhas com responsabilidades misturadas.
- Duplicação (scanner detecta blocos idênticos), números mágicos, código morto.
- Acoplamento: regra de negócio dentro de handler HTTP; acesso a banco espalhado.
- Testabilidade: dependências injetáveis? É possível testar sem rede/banco reais?
