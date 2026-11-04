# CODE SENTINEL — RELATÓRIO DE INTEGRIDADE

> Gerado em 2026-11-04T00:13:33+00:00 · CODE SENTINEL v1.0.0 · confiança da avaliação: **Alta**

## Resumo executivo

O vulnerable-shop não está apto para nenhum ambiente além de desenvolvimento. Há execução remota de código comprovada por fluxo de dados (eval e exec com entrada da requisição), SQL injection, credenciais de nuvem e de banco de dados no código, um módulo que não compila e duas regras de negócio quebradas confirmadas pelos próprios testes. A prioridade imediata é remover/rotacionar segredos e eliminar eval/exec/concatenação SQL; em seguida corrigir pricing.js e atualizar dependências com CVEs.

## 1. Projeto e tecnologias

| Item | Valor |
|---|---|
| Nome do projeto | vulnerable-shop |
| Linguagens (arquivos) | js (7), py (1) |
| Frameworks / bibliotecas | Express |
| Ferramentas de teste declaradas | node:test (nativo) |
| Linhas de código-fonte | 199 |
| Arquivos de teste | 1 |
| CI configurado | não |

## 2. Ferramentas utilizadas

| Ferramenta | Versão | Status | Verificações | Observação |
|---|---|---|---|---|
| scan_patterns.py | 1.0 | executada | sast_heuristic, error_handling_heuristic, perf_heuristic, duplication, complexity_heuristic | 8 arquivos, 29 achados |
| scan_secrets.py | 1.0 | executada | secrets | 9 arquivos, 5 achados |
| py-syntax | python 3.13.18 (ast.parse) | executada | syntax | 0 achados |
| node-syntax | node v22.23.4 | executada | syntax | 1 achados |
| tsc | - | não se aplica | types | sem tsconfig.json |
| eslint | - | não executada | lint | projeto sem configuração ESLint (ver references/tool-matrix.md para config sugerida; criar só com autorização) |
| prettier | - | não executada | format | sem configuração Prettier |
| npm-audit | npm 10.9.9 | executada | deps | 9 achados |
| pip-audit | - | não executada | deps | ha código Python mas nenhum requirements.txt/pyproject.toml: dependências Python não declaradas nem auditáveis |
| semgrep | 1.183.0 | executada | sast | apenas ruleset local (registry semgrep.dev inacessível: sem rede ou bloqueado) |
| bandit | bandit 1.9.4 | executada | sast | 6 achados |
| ruff | ruff 0.16.9 | executada | lint | 2 achados |
| tests | node:test | executada | tests_executed, coverage | 2 achados |
| Revisão manual (Claude) | - | executada | manual_security_review, manual_logic_review, manual_error_review | src/ inteiro linha a linha (projeto pequeno); src/legacy por amostragem |

## 3. Testes

- **Executados** com `node:test`: 6 testes — ✅ 4 passaram, ❌ 2 falharam, ⏭ 0 ignorados.

**Verificações não executadas e motivos:**

- `tsc` (não se aplica): sem tsconfig.json
- `eslint` (não executada): projeto sem configuração ESLint (ver references/tool-matrix.md para config sugerida; criar só com autorização)
- `prettier` (não executada): sem configuração Prettier
- `pip-audit` (não executada): ha código Python mas nenhum requirements.txt/pyproject.toml: dependências Python não declaradas nem auditáveis

## 4. Resumo dos problemas

**Total de problemas:** 52 (após remover duplicados entre ferramentas; 68 brutos)

| Gravidade | Quantidade |
|---|---|
| CRÍTICO | 10 |
| ALTO | 16 |
| MÉDIO | 15 |
| BAIXO | 11 |
| INFORMATIVO | 0 |

| Classificação | Quantidade |
|---|---|
| Confirmado | 29 |
| Risco potencial | 22 |
| Hipótese | 1 |

## 5. Vulnerabilidades identificadas

- [CRÍTICO] Dependência vulnerável: minimist (1.0.0 - 1.2.5) — `package-lock.json:1` (Confirmado)
- [CRÍTICO] Comando de shell montado com concatenação (Command Injection). — `src/legacy/report.py:14` (Confirmado)
- [CRÍTICO] Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código. — `src/legacy/report.py:20` (Confirmado)
- [CRÍTICO] Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código. — `src/legacy/report.py:26` (Confirmado)
- [CRÍTICO] AWS Access Key ID exposta — `src/server.js:15` (Confirmado)
- [CRÍTICO] Entrada da requisição chega a uma consulta SQL montada dinamicamente (SQL Injection). — `src/server.js:19` (Confirmado)
- [CRÍTICO] Entrada da requisição chega a um comando de shell (Command Injection / RCE). — `src/server.js:26` (Confirmado)
- [CRÍTICO] Entrada da requisição é avaliada como código (eval/new Function) — execução remota de código. — `src/server.js:49` (Confirmado)
- [CRÍTICO] Possível SQL Injection (consulta formatada) — `src/legacy/report.py:13` (Risco potencial)
- [ALTO] Dependência vulnerável: body-parser (<=1.20.8) — `package-lock.json:1` (Confirmado)
- [ALTO] Dependência vulnerável: express (<=4.21.2 || 5.0.0-alpha.1 - 5.0.0) — `package-lock.json:1` (Confirmado)
- [ALTO] Dependência vulnerável: lodash (<=4.17.23) — `package-lock.json:1` (Confirmado)
- [ALTO] Dependência vulnerável: path-to-regexp (<=0.1.12) — `package-lock.json:1` (Confirmado)
- [ALTO] Dependência vulnerável: qs (<=6.16.0) — `package-lock.json:1` (Confirmado)
- [ALTO] URL de banco de dados com senha embutida — `src/db.js:2` (Confirmado)
- [ALTO] Credencial hardcoded (senha/segredo/token literal) — `src/db.js:4` (Confirmado)
- [ALTO] Credencial hardcoded (senha/segredo/token literal) — `src/legacy/report.py:8` (Confirmado)
- [ALTO] Credencial hardcoded (senha/segredo/token literal) — `src/server.js:14` (Confirmado)
- [ALTO] Rota sensível sem middleware de autenticação/autorização — `src/server.js:29` (Risco potencial)
- [ALTO] Possível Path Traversal (caminho de arquivo vindo da requisição) — `src/server.js:35` (Risco potencial)
- [MÉDIO] request_without_timeout (B113) — `src/legacy/report.py:30` (Risco potencial)
- [MÉDIO] Detalhes internos de erro expostos ao cliente — `src/server.js:20` (Risco potencial)
- [MÉDIO] Endpoint de login sem middleware (rate limit/validação) visível — `src/server.js:38` (Risco potencial)
- [MÉDIO] Algoritmo de hash fraco (MD5/SHA-1) — `src/server.js:40` (Risco potencial)
- [MÉDIO] Dado sensível enviado para log — `src/server.js:41` (Risco potencial)
- [MÉDIO] Aleatoriedade previsível para valor de segurança — `src/server.js:43` (Risco potencial)
- [MÉDIO] JWT assinado com segredo literal no código. — `src/server.js:45` (Risco potencial)
- [BAIXO] Dependência vulnerável: cookie (<0.7.0) — `package-lock.json:1` (Confirmado)
- [BAIXO] Dependência vulnerável: send (<0.19.0) — `package-lock.json:1` (Confirmado)
- [BAIXO] Dependência vulnerável: serve-static (<=1.16.0) — `package-lock.json:1` (Confirmado)
- [BAIXO] blacklist (B403) — `src/legacy/report.py:3` (Confirmado)

## 6. Problemas de performance

- [MÉDIO] Coleção em memória 'sessionCache' só cresce (possível vazamento) — `src/server.js:16`
- [BAIXO] SELECT * em consulta — `src/legacy/report.py:13`
- [BAIXO] SELECT * em consulta — `src/server.js:19`
- [BAIXO] I/O síncrono (bloqueia o event loop) — `src/server.js:72`
- [BAIXO] setInterval sem clearInterval — `src/server.js:76`

## 7. Cobertura de testes

- Linhas: **12.4%** · Branches: 100.0% · Funções: 100.0% (fonte: node --experimental-test-coverage)
- Categorias de casos de borda presentes nos testes: entrada inválida, vazio/nulo

## 8. Principais pontos de risco

1. **Dependência vulnerável: minimist (1.0.0 - 1.2.5)** (`package-lock.json:1`) — Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.
2. **Erro de sintaxe (arquivo não compila)** (`src/broken.js:2`) — O modulo falha ao ser carregado; tudo que o importa quebra em tempo de execução ou de build.
3. **Comando de shell montado com concatenação (Command Injection).** (`src/legacy/report.py:14`) — Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).
4. **Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código.** (`src/legacy/report.py:20`) — Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).
5. **Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código.** (`src/legacy/report.py:26`) — Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).
6. **AWS Access Key ID exposta** (`src/server.js:15`) — Qualquer pessoa com acesso ao código, ao histórico git ou ao bundle pode usar a credencial para acessar o serviço/dados protegidos.
7. **Entrada da requisição chega a uma consulta SQL montada dinamicamente (SQL Injection).** (`src/server.js:19`) — Fluxo de dados comprovado da entrada da requisição até o ponto perigoso (taint).

## 9. Achados detalhados

#### 1. [CRÍTICO] Dependência vulnerável: minimist (1.0.0 - 1.2.5)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência direta) |
| **Origem** | npm-audit |
| **Referência** | CWE-1321 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** Prototype Pollution in minimist

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** Atualizar para minimist@1.2.8

**Evidência:**

```
https://github.com/advisories/GHSA-vh95-rmgr-6w4m, https://github.com/advisories/GHSA-xvch-5gv4-984h
```


#### 2. [CRÍTICO] Erro de sintaxe (arquivo não compila)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/broken.js:2` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Integridade e lógica |
| **Probabilidade** | certa |
| **Origem** | node-syntax |

**O que está acontecendo:** SyntaxError: Unexpected token '{'

**Como pode quebrar o sistema:** O modulo falha ao ser carregado; tudo que o importa quebra em tempo de execução ou de build.

**Impacto potencial:** Indisponibilidade da funcionalidade/aplicação.

**Sugestão de correção:** Corrigir a sintaxe e adicionar verificação (lint/tsc/build) no CI.

**Evidência:**

```
SyntaxError: Unexpected token '{'
```


#### 3. [CRÍTICO] Comando de shell montado com concatenação (Command Injection).

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:14` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | semgrep, bandit, pattern-scan |
| **Referência** | CWE-78 · A03:2021 - Injection |

**O que está acontecendo:** Comando de shell montado com concatenação (Command Injection).

**Como pode quebrar o sistema:** Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).

**Impacto potencial:** Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).

**Sugestão de correção:** Ver mensagem da regra e references/audit-checklist.md.

**Evidência:**

```
requires login
```


#### 4. [CRÍTICO] Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código.

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:20` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | semgrep, pattern-scan, bandit |
| **Referência** | CWE-502 · A08:2021 - Software and Data Integrity Failures |

**O que está acontecendo:** Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código.

**Como pode quebrar o sistema:** Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).

**Impacto potencial:** Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).

**Sugestão de correção:** Ver mensagem da regra e references/audit-checklist.md.

**Evidência:**

```
requires login
```


#### 5. [CRÍTICO] Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código.

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:26` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | semgrep, pattern-scan, bandit |
| **Referência** | CWE-502 · A08:2021 - Software and Data Integrity Failures |

**O que está acontecendo:** Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código.

**Como pode quebrar o sistema:** Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).

**Impacto potencial:** Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).

**Sugestão de correção:** Ver mensagem da regra e references/audit-checklist.md.

**Evidência:**

```
requires login
```


#### 6. [CRÍTICO] AWS Access Key ID exposta

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:15` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | secret-scan |
| **Referência** | CWE-798 · A07:2021 / ASVS V2.10, V6.4 |

**O que está acontecendo:** Valor sensível literal encontrado (AKIA************TW).

**Como pode quebrar o sistema:** Qualquer pessoa com acesso ao código, ao histórico git ou ao bundle pode usar a credencial para acessar o serviço/dados protegidos.

**Impacto potencial:** Acesso não autorizado, movimentação lateral, custo financeiro, vazamento de dados.

**Sugestão de correção:** Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.

**Evidência:**

```
const AWS_ACCESS_KEY_ID = 'AKIA************TW';
```

**Código corrigido / exemplo:**

```
const apiKey = process.env.API_KEY;
if (!apiKey) throw new Error('API_KEY não configurada');
```


#### 7. [CRÍTICO] Entrada da requisição chega a uma consulta SQL montada dinamicamente (SQL Injection).

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:19` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | semgrep, pattern-scan |
| **Referência** | CWE-89 · A03:2021 - Injection |

**O que está acontecendo:** Entrada da requisição chega a uma consulta SQL montada dinamicamente (SQL Injection).

**Como pode quebrar o sistema:** Fluxo de dados comprovado da entrada da requisição até o ponto perigoso (taint).

**Impacto potencial:** Fluxo de dados comprovado da entrada da requisição até o ponto perigoso (taint).

**Sugestão de correção:** Ver mensagem da regra e references/audit-checklist.md.

**Evidência:**

```
requires login
```


#### 8. [CRÍTICO] Entrada da requisição chega a um comando de shell (Command Injection / RCE).

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:26` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | semgrep, pattern-scan |
| **Referência** | CWE-78 · A03:2021 - Injection |

**O que está acontecendo:** Entrada da requisição chega a um comando de shell (Command Injection / RCE).

**Como pode quebrar o sistema:** Fluxo de dados comprovado da entrada da requisição até o ponto perigoso (taint).

**Impacto potencial:** Fluxo de dados comprovado da entrada da requisição até o ponto perigoso (taint).

**Sugestão de correção:** Ver mensagem da regra e references/audit-checklist.md.

**Evidência:**

```
requires login
```


#### 9. [CRÍTICO] Entrada da requisição é avaliada como código (eval/new Function) — execução remota de código.

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:49` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | semgrep, pattern-scan |
| **Referência** | CWE-95 · A03:2021 - Injection |

**O que está acontecendo:** Entrada da requisição é avaliada como código (eval/new Function) — execução remota de código.

**Como pode quebrar o sistema:** Fluxo de dados comprovado da entrada da requisição até o ponto perigoso (taint).

**Impacto potencial:** Fluxo de dados comprovado da entrada da requisição até o ponto perigoso (taint).

**Sugestão de correção:** Ver mensagem da regra e references/audit-checklist.md.

**Evidência:**

```
requires login
```


#### 10. [CRÍTICO] Possível SQL Injection (consulta formatada)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:13` |
| **Gravidade** | CRÍTICO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | pattern-scan, semgrep, bandit |
| **Referência** | CWE-89 · A03:2021 |

**O que está acontecendo:** A consulta SQL e construida com f-string/format/concatenação.

**Como pode quebrar o sistema:** Entrada maliciosa altera a consulta.

**Impacto potencial:** Entrada maliciosa altera a consulta.

**Sugestão de correção:** Usar parametros do driver: cursor.execute(sql, (valor,)).

**Evidência:**

```
cursor.execute(f"SELECT * FROM reports WHERE name = '{name}'")
```

**Código corrigido / exemplo:**

```
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```


#### 11. [ALTO] Dependência vulnerável: body-parser (<=1.20.8)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência transitiva) |
| **Origem** | npm-audit |
| **Referência** | CWE-248, CWE-405, CWE-770 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** body-parser vulnerable to Denial of Service via trailing bytes after a compressed request body; body-parser vulnerable to denial of service when invalid limit value silently disables size enforcement; body-parser vulnerable to denial of service when url encoding is enabled

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** Atualizar para express@4.22.3

**Evidência:**

```
https://github.com/advisories/GHSA-27r3-jxmh-p828, https://github.com/advisories/GHSA-qwcr-r2fm-qrc7, https://github.com/advisories/GHSA-v422-hmwv-36x6
```


#### 12. [ALTO] Dependência vulnerável: express (<=4.21.2 || 5.0.0-alpha.1 - 5.0.0)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência direta) |
| **Origem** | npm-audit |
| **Referência** | CWE-1286, CWE-601, CWE-79 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** Express.js Open Redirect in malformed URLs; express vulnerable to XSS via response.redirect()

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** Atualizar para express@4.22.3

**Evidência:**

```
https://github.com/advisories/GHSA-qw6h-vgh9-j6wx, https://github.com/advisories/GHSA-rv95-896h-c2vc
```


#### 13. [ALTO] Dependência vulnerável: lodash (<=4.17.23)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência direta) |
| **Origem** | npm-audit |
| **Referência** | CWE-1321, CWE-1333, CWE-400, CWE-77, CWE-770, CWE-94 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** Command Injection in lodash; Lodash has Prototype Pollution Vulnerability in `_.unset` and `_.omit` functions; Prototype Pollution in lodash; Regular Expression Denial of Service (ReDoS) in lodash; lodash vulnerable to Code Injection via `_.template` imports key names

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** Atualizar para lodash@4.18.1

**Evidência:**

```
https://github.com/advisories/GHSA-29mw-wpgm-hmr9, https://github.com/advisories/GHSA-35jh-r3h4-6jhm, https://github.com/advisories/GHSA-p6mc-m468-83gw, https://github.com/advisories/GHSA-r5fr-rjxr-66jc, https://github.com/advisories/GHSA-xxjr-mmjv-4gpg
```


#### 14. [ALTO] Dependência vulnerável: path-to-regexp (<=0.1.12)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência transitiva) |
| **Origem** | npm-audit |
| **Referência** | CWE-1333 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** path-to-regexp contains a ReDoS; path-to-regexp outputs backtracking regular expressions; path-to-regexp vulnerable to Regular Expression Denial of Service via multiple route parameters

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** Atualizar para express@4.22.3

**Evidência:**

```
https://github.com/advisories/GHSA-37ch-88jc-xwx2, https://github.com/advisories/GHSA-9wv6-86v2-598j, https://github.com/advisories/GHSA-rhx6-c78j-4q9w
```


#### 15. [ALTO] Dependência vulnerável: qs (<=6.16.0)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência transitiva) |
| **Origem** | npm-audit |
| **Referência** | CWE-1321, CWE-20, CWE-248, CWE-703, CWE-704 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** qs : qs.stringify with arrayFormat 'comma' throws an uncaught TypeError on array elements carrying a non-callable own toString (DoS); qs vulnerable to Prototype Pollution; qs's arrayLimit bypass in comma parsing allows denial of service; qs's arrayLimit bypass in its bracket notation allows DoS via 

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** Atualizar para express@4.22.3

**Evidência:**

```
https://github.com/advisories/GHSA-4mjr-xmp4-gh2g, https://github.com/advisories/GHSA-6pq8-jhm2-2vcw, https://github.com/advisories/GHSA-6rw7-vpxm-498p, https://github.com/advisories/GHSA-hrpp-h998-j3pp, https://github.com/advisories/GHSA-w7fw-mjwx-w883
```


#### 16. [ALTO] URL de banco de dados com senha embutida

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/db.js:2` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | secret-scan |
| **Referência** | CWE-798 · A07:2021 / ASVS V2.10, V6.4 |

**O que está acontecendo:** Valor sensível literal encontrado (Sup3*******Pw).

**Como pode quebrar o sistema:** Qualquer pessoa com acesso ao código, ao histórico git ou ao bundle pode usar a credencial para acessar o serviço/dados protegidos.

**Impacto potencial:** Acesso não autorizado, movimentação lateral, custo financeiro, vazamento de dados.

**Sugestão de correção:** Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.

**Evidência:**

```
const DATABASE_URL = 'postgres://admin:Sup3*******Pw@db.internal:5432/shop';
```

**Código corrigido / exemplo:**

```
const apiKey = process.env.API_KEY;
if (!apiKey) throw new Error('API_KEY não configurada');
```


#### 17. [ALTO] Credencial hardcoded (senha/segredo/token literal)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/db.js:4` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | secret-scan |
| **Referência** | CWE-798 · A07:2021 / ASVS V2.10, V6.4 |

**O que está acontecendo:** Valor sensível literal encontrado (5f4d************99).

**Como pode quebrar o sistema:** Qualquer pessoa com acesso ao código, ao histórico git ou ao bundle pode usar a credencial para acessar o serviço/dados protegidos.

**Impacto potencial:** Acesso não autorizado, movimentação lateral, custo financeiro, vazamento de dados.

**Sugestão de correção:** Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.

**Evidência:**

```
const users = [{ id: 1, name: 'ana', passwordHash: '5f4d************99' }];
```

**Código corrigido / exemplo:**

```
const passwordHash = process.env.PASSWORDHASH;
if (!passwordHash) throw new Error('PASSWORDHASH não configurada');
```


#### 18. [ALTO] Credencial hardcoded (senha/segredo/token literal)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:8` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | secret-scan |
| **Referência** | CWE-798 · A07:2021 / ASVS V2.10, V6.4 |

**O que está acontecendo:** Valor sensível literal encontrado (fixt************6f).

**Como pode quebrar o sistema:** Qualquer pessoa com acesso ao código, ao histórico git ou ao bundle pode usar a credencial para acessar o serviço/dados protegidos.

**Impacto potencial:** Acesso não autorizado, movimentação lateral, custo financeiro, vazamento de dados.

**Sugestão de correção:** Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.

**Evidência:**

```
PAYMENTS_API_KEY = "fixt************6f"
```

**Código corrigido / exemplo:**

```
import os
PAYMENTS_API_KEY = os.environ["PAYMENTS_API_KEY"]  # falha cedo se ausente
```


#### 19. [ALTO] Média de avaliações retorna NaN para produto sem avaliações

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/pricing.js:5` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Integridade e lógica |
| **Probabilidade** | alta |
| **Origem** | manual |
| **Referência** | CWE-369 |

**O que está acontecendo:** calculateAverageRating([]) divide 0 por 0 e retorna NaN; db.ratingsFor() retorna [] para produtos novos.

**Como pode quebrar o sistema:** GET /products/:id/rating responde {"average": null} (NaN serializado) e a UI exibe 'NaN estrelas'; ordenações por nota ficam inconsistentes.

**Impacto potencial:** Todo produto sem avaliações quebra a exibição de nota.

**Sugestão de correção:** Tratar lista vazia explicitamente antes de dividir.

**Evidência:**

```
test/pricing.test.js › 'media de avaliacoes com lista vazia retorna 0' falha: Expected values to be strictly equal (NaN !== 0)
```

**Código corrigido / exemplo:**

```
function calculateAverageRating(ratings) {
  if (!Array.isArray(ratings) || ratings.length === 0) return 0;
  return ratings.reduce((s, r) => s + r, 0) / ratings.length;
}
```


#### 20. [ALTO] Desconto acima de 100% gera preço negativo

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/pricing.js:9` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Integridade e lógica |
| **Probabilidade** | media |
| **Origem** | manual |

**O que está acontecendo:** applyDiscount não valida o percentual; applyDiscount(100, 150) retorna -50.

**Como pode quebrar o sistema:** Cupom mal configurado (ou manipulado) gera pedido com valor negativo — crédito indevido ao cliente.

**Impacto potencial:** Perda financeira direta.

**Sugestão de correção:** Validar 0 ≤ percent ≤ 100 e price ≥ 0, lançando RangeError.

**Evidência:**

```
test/pricing.test.js › 'desconto invalido (acima de 100%) deve lancar erro' falha: Missing expected exception (RangeError)
```

**Código corrigido / exemplo:**

```
if (percent < 0 || percent > 100) throw new RangeError('percentual fora de 0..100');
```


#### 21. [ALTO] Dependência 'jsonwebtoken' usada mas não declarada

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:7` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Integridade e lógica |
| **Probabilidade** | alta |
| **Origem** | pattern-scan |

**O que está acontecendo:** 'jsonwebtoken' e importado, mas não consta em dependencies/devDependencies do package.json.

**Como pode quebrar o sistema:** Em uma instalação limpa (npm ci, deploy, CI) o require falha com MODULE_NOT_FOUND e o processo não sobe; hoje so funciona por acaso (pacote transitivo ou instalado globalmente).

**Impacto potencial:** Falha de deploy / indisponibilidade.

**Sugestão de correção:** Declarar a dependência com versão fixada: npm install jsonwebtoken --save (com autorização).

**Evidência:**

```
const jwt = require('jsonwebtoken'); // dependencia NAO declarada no package.json
```


#### 22. [ALTO] Credencial hardcoded (senha/segredo/token literal)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:14` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | secret-scan |
| **Referência** | CWE-798 · A07:2021 / ASVS V2.10, V6.4 |

**O que está acontecendo:** Valor sensível literal encontrado (supe************23).

**Como pode quebrar o sistema:** Qualquer pessoa com acesso ao código, ao histórico git ou ao bundle pode usar a credencial para acessar o serviço/dados protegidos.

**Impacto potencial:** Acesso não autorizado, movimentação lateral, custo financeiro, vazamento de dados.

**Sugestão de correção:** Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.

**Evidência:**

```
const JWT_SECRET = 'supe************23';
```

**Código corrigido / exemplo:**

```
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error('JWT_SECRET não configurada');
```


#### 23. [ALTO] Teste falhando: media de avaliacoes com lista vazia retorna 0

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `test/pricing.test.js:1` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Testes automatizados |
| **Probabilidade** | certa |
| **Origem** | tests:node:test |

**O que está acontecendo:** Expected values to be strictly equal:

**Como pode quebrar o sistema:** Comportamento esperado pela suite não e atendido: ou ha bug no código, ou o teste esta desatualizado. Não ignorar.

**Impacto potencial:** Comportamento esperado pela suite não e atendido: ou ha bug no código, ou o teste esta desatualizado. Não ignorar.

**Sugestão de correção:** Investigar a causa raiz; corrigir o código ou o teste (nunca desabilitar).


#### 24. [ALTO] Teste falhando: desconto invalido (acima de 100%) deve lancar erro

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `test/pricing.test.js:1` |
| **Gravidade** | ALTO |
| **Classificação** | Confirmado |
| **Categoria** | Testes automatizados |
| **Probabilidade** | certa |
| **Origem** | tests:node:test |

**O que está acontecendo:** 'Missing expected exception (RangeError).'

**Como pode quebrar o sistema:** Comportamento esperado pela suite não e atendido: ou ha bug no código, ou o teste esta desatualizado. Não ignorar.

**Impacto potencial:** Comportamento esperado pela suite não e atendido: ou ha bug no código, ou o teste esta desatualizado. Não ignorar.

**Sugestão de correção:** Investigar a causa raiz; corrigir o código ou o teste (nunca desabilitar).


#### 25. [ALTO] Rota sensível sem middleware de autenticação/autorização

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:29` |
| **Gravidade** | ALTO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | alta |
| **Origem** | pattern-scan |
| **Referência** | CWE-862 · A01:2021 Broken Access Control / ASVS V4 |

**O que está acontecendo:** Rota administrativa/sensível registrada com o handler direto, sem middleware de auth visível.

**Como pode quebrar o sistema:** Qualquer cliente anonimo pode invocar a operação privilegiada.

**Impacto potencial:** Qualquer cliente anonimo pode invocar a operação privilegiada.

**Sugestão de correção:** Adicionar middleware de autenticação e verificação de papel (RBAC) antes do handler; confirmar se ha proteção global (app.use) antes de classificar como confirmado.

**Evidência:**

```
app.delete('/admin/users/:id', (req, res) => {
```

**Código corrigido / exemplo:**

```
app.delete('/admin/users/:id', requireAuth, requireRole('admin'), handler);
```


#### 26. [ALTO] Possível Path Traversal (caminho de arquivo vindo da requisição)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:35` |
| **Gravidade** | ALTO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | pattern-scan, semgrep |
| **Referência** | CWE-22 · A01:2021 Broken Access Control |

**O que está acontecendo:** Um caminho de arquivo e derivado de entrada do usuário.

**Como pode quebrar o sistema:** `../../etc/passwd` permite ler/escrever arquivos fora do diretório esperado.

**Impacto potencial:** `../../etc/passwd` permite ler/escrever arquivos fora do diretório esperado.

**Sugestão de correção:** Resolver o caminho com path.resolve e verificar que comeca com o diretório base; usar allowlist.

**Evidência:**

```
fs.readFile(path.join(__dirname, 'uploads', req.query.name), (err, data) => res.send(data));
```

**Código corrigido / exemplo:**

```
const p = path.resolve(BASE, name);
if (!p.startsWith(BASE + path.sep)) return res.sendStatus(400);
```


#### 27. [MÉDIO] ruff B006

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:11` |
| **Gravidade** | MÉDIO |
| **Classificação** | Confirmado |
| **Categoria** | Integridade e lógica |
| **Probabilidade** | desconhecida |
| **Origem** | ruff, pattern-scan |

**O que está acontecendo:** Do not use mutable data structures for argument defaults

**Como pode quebrar o sistema:** Violação de lint.

**Impacto potencial:** Violação de lint.

**Sugestão de correção:** Replace with `None`; initialize within function


#### 28. [MÉDIO] Exceção genérica capturada/silenciada

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:21` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Estabilidade e tratamento de erros |
| **Probabilidade** | media |
| **Origem** | pattern-scan |
| **Referência** | CWE-396 |

**O que está acontecendo:** `except:` / `except Exception: pass` engole qualquer erro (inclusive KeyboardInterrupt no bare except).

**Como pode quebrar o sistema:** Erros reais desaparecem; estado inconsistente; depuração muito difícil.

**Impacto potencial:** Erros reais desaparecem; estado inconsistente; depuração muito difícil.

**Sugestão de correção:** Capturar exceções específicas e logar.

**Evidência:**

```
except:
```


#### 29. [MÉDIO] request_without_timeout (B113)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:30` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | desconhecida |
| **Origem** | bandit, semgrep |
| **Referência** | CWE-400 |

**O que está acontecendo:** Call to requests without timeout

**Como pode quebrar o sistema:** Ver documentação do bandit para o teste.

**Impacto potencial:** Ver documentação do bandit para o teste.

**Sugestão de correção:** https://bandit.readthedocs.io/en/1.9.4/plugins/b113_request_without_timeout.html

**Evidência:**

```
29 def fetch_rates():
30     return requests.get("https://api.example.com/rates").json()

```


#### 30. [MÉDIO] Requisição HTTP sem timeout

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:30` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Estabilidade e tratamento de erros |
| **Probabilidade** | media |
| **Origem** | pattern-scan |
| **Referência** | CWE-400 |

**O que está acontecendo:** requests sem timeout espera indefinidamente.

**Como pode quebrar o sistema:** Workers ficam presos se o serviço remoto travar.

**Impacto potencial:** Workers ficam presos se o serviço remoto travar.

**Sugestão de correção:** Passar timeout=(3.05, 10).

**Evidência:**

```
return requests.get("https://api.example.com/rates").json()
```


#### 31. [MÉDIO] Coleção em memória 'sessionCache' só cresce (possível vazamento)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:16` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Performance |
| **Probabilidade** | alta |
| **Origem** | pattern-scan |
| **Referência** | CWE-401 |

**O que está acontecendo:** 'sessionCache' e um objeto/array/Map no escopo do modulo que recebe itens e nunca e limpo.

**Como pode quebrar o sistema:** Em processo de longa duração a memória cresce a cada requisição até o OOM/crash.

**Impacto potencial:** Degradação progressiva e queda do serviço.

**Sugestão de correção:** Usar cache com limite e expiração (LRU com max/ttl) ou armazenamento externo.

**Evidência:**

```
const sessionCache = {};
```

**Código corrigido / exemplo:**

```
const { LRUCache } = require('lru-cache');
const cache = new LRUCache({ max: 1000, ttl: 60_000 });
```


#### 32. [MÉDIO] Detalhes internos de erro expostos ao cliente

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:20` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | pattern-scan |
| **Referência** | CWE-209 · A05:2021 |

**O que está acontecendo:** Mensagens/stack traces de exceções são devolvidas na resposta.

**Como pode quebrar o sistema:** Revela estrutura interna, consultas SQL e caminhos, facilitando ataques.

**Impacto potencial:** Revela estrutura interna, consultas SQL e caminhos, facilitando ataques.

**Sugestão de correção:** Logar o erro no servidor e responder mensagem genérica com ID de correlação.

**Evidência:**

```
if (err) return res.status(500).json({ error: err.stack });
```


#### 33. [MÉDIO] Endpoint de login sem middleware (rate limit/validação) visível

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:38` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | pattern-scan |
| **Referência** | CWE-307 · A07:2021 |

**O que está acontecendo:** Rota de autenticação recebe o handler diretamente.

**Como pode quebrar o sistema:** Sem limite de tentativas, permite força bruta e credential stuffing.

**Impacto potencial:** Sem limite de tentativas, permite força bruta e credential stuffing.

**Sugestão de correção:** Adicionar rate limiting (express-rate-limit) e bloqueio progressivo.

**Evidência:**

```
app.post('/login', (req, res) => {
```


#### 34. [MÉDIO] Algoritmo de hash fraco (MD5/SHA-1)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:40` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | pattern-scan, semgrep |
| **Referência** | CWE-327 · A02:2021 |

**O que está acontecendo:** MD5/SHA-1 são inadequados para senhas e integridade.

**Como pode quebrar o sistema:** Senhas com hash rápido são quebradas por força bruta; colisoes possibilitam falsificação.

**Impacto potencial:** Senhas com hash rápido são quebradas por força bruta; colisoes possibilitam falsificação.

**Sugestão de correção:** Senhas: bcrypt/scrypt/argon2. Integridade: SHA-256+ ou HMAC.

**Evidência:**

```
const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
```

**Código corrigido / exemplo:**

```
const hash = await bcrypt.hash(password, 12);
```


#### 35. [MÉDIO] Dado sensível enviado para log

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:41` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | pattern-scan |
| **Referência** | CWE-532 · A09:2021 |

**O que está acontecendo:** Valores sensíveis são registrados em log.

**Como pode quebrar o sistema:** Logs são copiados para varios sistemas e pessoas.

**Impacto potencial:** Logs são copiados para varios sistemas e pessoas.

**Sugestão de correção:** Remover/mascarar o campo antes de logar.

**Evidência:**

```
console.log('login attempt', req.body.username, req.body.password);
```


#### 36. [MÉDIO] Aleatoriedade previsível para valor de segurança

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:43` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | pattern-scan |
| **Referência** | CWE-338 · A02:2021 |

**O que está acontecendo:** Math.random não e criptograficamente seguro.

**Como pode quebrar o sistema:** Tokens/IDs de sessão podem ser previstos.

**Impacto potencial:** Tokens/IDs de sessão podem ser previstos.

**Sugestão de correção:** Usar crypto.randomBytes / crypto.randomUUID.

**Evidência:**

```
const token = Math.random().toString(36).slice(2);
```


#### 37. [MÉDIO] JWT assinado com segredo literal no código.

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:45` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | media |
| **Origem** | semgrep |
| **Referência** | CWE-798 · A07:2021 - Identification and Authentication Failures |

**O que está acontecendo:** JWT assinado com segredo literal no código.

**Como pode quebrar o sistema:** Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).

**Impacto potencial:** Padrão de vulnerabilidade detectado por regra Semgrep (confirmar contexto).

**Sugestão de correção:** Ver mensagem da regra e references/audit-checklist.md.

**Evidência:**

```
requires login
```


#### 38. [MÉDIO] JSON.parse sem tratamento de erro

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:53` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Estabilidade e tratamento de erros |
| **Probabilidade** | alta |
| **Origem** | pattern-scan |
| **Referência** | CWE-20 |

**O que está acontecendo:** JSON.parse lanca SyntaxError com entrada inválida/vazia.

**Como pode quebrar o sistema:** Payload malformado derruba a requisição (500) ou o processo, se fora de handler.

**Impacto potencial:** Payload malformado derruba a requisição (500) ou o processo, se fora de handler.

**Sugestão de correção:** Envolver em try/catch e responder 400 com mensagem clara.

**Evidência:**

```
const prefs = JSON.parse(req.headers['x-profile']);
```

**Código corrigido / exemplo:**

```
let data;
try { data = JSON.parse(raw); }
catch { return res.status(400).json({ error: 'JSON inválido' }); }
```


#### 39. [MÉDIO] forEach com callback async (não aguarda as Promises)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:64` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Integridade e lógica |
| **Probabilidade** | alta |
| **Origem** | pattern-scan |

**O que está acontecendo:** Array.forEach ignora as Promises retornadas.

**Como pode quebrar o sistema:** O código seguinte executa antes do fim das operações; erros viram unhandledRejection.

**Impacto potencial:** O código seguinte executa antes do fim das operações; erros viram unhandledRejection.

**Sugestão de correção:** Usar for...of com await, ou await Promise.all(items.map(async ...)).

**Evidência:**

```
recipients.forEach(async (r) => {
```

**Código corrigido / exemplo:**

```
for (const item of items) {
  await process(item);
}
```


#### 40. [MÉDIO] Exceção silenciada (catch vazio)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:73` |
| **Gravidade** | MÉDIO |
| **Classificação** | Risco potencial |
| **Categoria** | Estabilidade e tratamento de erros |
| **Probabilidade** | media |
| **Origem** | pattern-scan |
| **Referência** | CWE-390 |

**O que está acontecendo:** O erro e capturado e descartado sem log nem tratamento.

**Como pode quebrar o sistema:** Falhas reais passam despercebidas; o sistema continua em estado inconsistente.

**Impacto potencial:** Falhas reais passam despercebidas; o sistema continua em estado inconsistente.

**Sugestão de correção:** Logar com contexto e propagar ou tratar explicitamente.

**Evidência:**

```
} catch (e) {}
```

**Código corrigido / exemplo:**

```
catch (err) {
  logger.error({ err }, 'falha ao processar X');
  throw err;
}
```


#### 41. [MÉDIO] Sessões em memória do processo quebram com múltiplas instâncias

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:44` |
| **Gravidade** | MÉDIO |
| **Classificação** | Hipótese |
| **Categoria** | Estabilidade e tratamento de erros |
| **Probabilidade** | desconhecida |
| **Origem** | manual |

**O que está acontecendo:** Tokens são guardados em sessionCache (objeto local do processo).

**Como pode quebrar o sistema:** Com 2+ réplicas atrás de um balanceador, o usuário perde a sessão aleatoriamente; um restart desloga todos.

**Impacto potencial:** Logouts aleatórios em produção escalada.

**Sugestão de correção:** Usar store compartilhado (Redis) com TTL, ou JWT verificado sem estado no servidor.

**Evidência:**

```
Depende da topologia de deploy (não disponível no repositório).
```


#### 42. [BAIXO] Dependência vulnerável: cookie (<0.7.0)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | BAIXO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência transitiva) |
| **Origem** | npm-audit |
| **Referência** | CWE-74 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** cookie accepts cookie name, path, and domain with out of bounds characters

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** Atualizar para express@4.22.3

**Evidência:**

```
https://github.com/advisories/GHSA-pxg6-pf52-xh8x
```


#### 43. [BAIXO] Dependência vulnerável: send (<0.19.0)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | BAIXO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência transitiva) |
| **Origem** | npm-audit |
| **Referência** | CWE-79 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** send vulnerable to template injection that can lead to XSS

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** Atualizar para express@4.22.3

**Evidência:**

```
https://github.com/advisories/GHSA-m6fv-jmcg-4jfg
```


#### 44. [BAIXO] Dependência vulnerável: serve-static (<=1.16.0)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `package-lock.json:1` |
| **Gravidade** | BAIXO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | depende da alcançabilidade (dependência transitiva) |
| **Origem** | npm-audit |
| **Referência** | CWE-79 · A06:2021 Vulnerable and Outdated Components |

**O que está acontecendo:** serve-static vulnerable to template injection that can lead to XSS

**Como pode quebrar o sistema:** Versão instalada possui vulnerabilidade pública (CVE/GHSA). O impacto real depende de o código vulnerável ser alcançável pelo projeto.

**Impacto potencial:** Conforme o advisory (ver links).

**Sugestão de correção:** `npm audit fix` resolve

**Evidência:**

```
https://github.com/advisories/GHSA-cm22-4g7w-348p
```


#### 45. [BAIXO] blacklist (B403)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:3` |
| **Gravidade** | BAIXO |
| **Classificação** | Confirmado |
| **Categoria** | Segurança e vulnerabilidades |
| **Probabilidade** | desconhecida |
| **Origem** | bandit |
| **Referência** | CWE-502 |

**O que está acontecendo:** Consider possible security implications associated with pickle module.

**Como pode quebrar o sistema:** Ver documentação do bandit para o teste.

**Impacto potencial:** Ver documentação do bandit para o teste.

**Sugestão de correção:** https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b403-import-pickle

**Evidência:**

```
2 import os
3 import pickle
4 

```


#### 46. [BAIXO] ruff E722

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:21` |
| **Gravidade** | BAIXO |
| **Classificação** | Confirmado |
| **Categoria** | Manutenibilidade |
| **Probabilidade** | desconhecida |
| **Origem** | ruff |

**O que está acontecendo:** Do not use bare `except`

**Como pode quebrar o sistema:** Violação de lint.

**Impacto potencial:** Violação de lint.

**Sugestão de correção:** Ajustar conforme a regra.


#### 47. [BAIXO] SELECT * em consulta

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/legacy/report.py:13` |
| **Gravidade** | BAIXO |
| **Classificação** | Risco potencial |
| **Categoria** | Performance |
| **Probabilidade** | baixa |
| **Origem** | pattern-scan |

**O que está acontecendo:** Consulta traz todas as colunas.

**Como pode quebrar o sistema:** Trafega dados desnecessarios/sensíveis; quebra com mudancas de schema.

**Impacto potencial:** Trafega dados desnecessarios/sensíveis; quebra com mudancas de schema.

**Sugestão de correção:** Selecionar apenas as colunas necessarias.

**Evidência:**

```
cursor.execute(f"SELECT * FROM reports WHERE name = '{name}'")
```


#### 48. [BAIXO] parseInt sem base (radix) e sem validação de NaN

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/pricing.js:13` |
| **Gravidade** | BAIXO |
| **Classificação** | Risco potencial |
| **Categoria** | Integridade e lógica |
| **Probabilidade** | media |
| **Origem** | pattern-scan |

**O que está acontecendo:** parseInt sem radix/validação pode devolver NaN ou valor inesperado.

**Como pode quebrar o sistema:** NaN se propaga silenciosamente em calculos e consultas.

**Impacto potencial:** NaN se propaga silenciosamente em calculos e consultas.

**Sugestão de correção:** Number.parseInt(v, 10) e validar Number.isNaN / Number.isInteger.

**Evidência:**

```
return parseInt(value);
```


#### 49. [BAIXO] SELECT * em consulta

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:19` |
| **Gravidade** | BAIXO |
| **Classificação** | Risco potencial |
| **Categoria** | Performance |
| **Probabilidade** | baixa |
| **Origem** | pattern-scan |

**O que está acontecendo:** Consulta traz todas as colunas.

**Como pode quebrar o sistema:** Trafega dados desnecessarios/sensíveis; quebra com mudancas de schema.

**Impacto potencial:** Trafega dados desnecessarios/sensíveis; quebra com mudancas de schema.

**Sugestão de correção:** Selecionar apenas as colunas necessarias.

**Evidência:**

```
db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => {
```


#### 50. [BAIXO] I/O síncrono (bloqueia o event loop)

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:72` |
| **Gravidade** | BAIXO |
| **Classificação** | Risco potencial |
| **Categoria** | Performance |
| **Probabilidade** | media |
| **Origem** | pattern-scan |

**O que está acontecendo:** Chamada sincrona bloqueia o processo Node inteiro enquanto executa.

**Como pode quebrar o sistema:** Sob carga, todas as requisições concorrentes ficam paradas aguardando.

**Impacto potencial:** Sob carga, todas as requisições concorrentes ficam paradas aguardando.

**Sugestão de correção:** Usar as versões assíncronas (fs/promises) em código de requisição.

**Evidência:**

```
return JSON.parse(fs.readFileSync('config.json', 'utf8'));
```


#### 51. [BAIXO] setInterval sem clearInterval

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/server.js:76` |
| **Gravidade** | BAIXO |
| **Classificação** | Risco potencial |
| **Categoria** | Performance |
| **Probabilidade** | media |
| **Origem** | pattern-scan |

**O que está acontecendo:** Timer recorrente nunca e cancelado.

**Como pode quebrar o sistema:** Impede shutdown limpo, mantem referências vivas e vaza em testes.

**Impacto potencial:** Impede shutdown limpo, mantem referências vivas e vaza em testes.

**Sugestão de correção:** Guardar o handle e chamar clearInterval no encerramento (ou .unref()).

**Evidência:**

```
setInterval(() => db.cleanup(), 60000);
```


#### 52. [BAIXO] Bloco de código duplicado

| Campo | Detalhe |
|---|---|
| **Arquivo / localização** | `src/validators.js:2` |
| **Gravidade** | BAIXO |
| **Classificação** | Risco potencial |
| **Categoria** | Manutenibilidade |
| **Probabilidade** | media |
| **Origem** | pattern-scan |

**O que está acontecendo:** Bloco de 8+ linhas idêntico em src/legacy/validators-old.js:3.

**Como pode quebrar o sistema:** Correções aplicadas em uma copia e esquecidas na outra geram comportamento divergente.

**Impacto potencial:** Correções aplicadas em uma copia e esquecidas na outra geram comportamento divergente.

**Sugestão de correção:** Extrair função/modulo compartilhado.


## 10. Recomendações de correção

**P0 — imediato (bloqueia homologação/produção)**

- Dependência vulnerável: minimist (1.0.0 - 1.2.5): Atualizar para minimist@1.2.8
- Erro de sintaxe (arquivo não compila): Corrigir a sintaxe e adicionar verificação (lint/tsc/build) no CI.
- Comando de shell montado com concatenação (Command Injection).: Ver mensagem da regra e references/audit-checklist.md.
- Desserialização insegura (pickle / yaml.load sem SafeLoader) — pode executar código. (2 ocorrências): Ver mensagem da regra e references/audit-checklist.md.
- AWS Access Key ID exposta: Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.
- Entrada da requisição chega a uma consulta SQL montada dinamicamente (SQL Injection).: Ver mensagem da regra e references/audit-checklist.md.
- Entrada da requisição chega a um comando de shell (Command Injection / RCE).: Ver mensagem da regra e references/audit-checklist.md.
- Entrada da requisição é avaliada como código (eval/new Function) — execução remota de código.: Ver mensagem da regra e references/audit-checklist.md.
- Possível SQL Injection (consulta formatada): Usar parametros do driver: cursor.execute(sql, (valor,)).

**P1 — antes de produção**

- Dependência vulnerável: body-parser (<=1.20.8): Atualizar para express@4.22.3
- Dependência vulnerável: express (<=4.21.2 || 5.0.0-alpha.1 - 5.0.0): Atualizar para express@4.22.3
- Dependência vulnerável: lodash (<=4.17.23): Atualizar para lodash@4.18.1
- Dependência vulnerável: path-to-regexp (<=0.1.12): Atualizar para express@4.22.3
- Dependência vulnerável: qs (<=6.16.0): Atualizar para express@4.22.3
- URL de banco de dados com senha embutida: Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.
- Credencial hardcoded (senha/segredo/token literal) (3 ocorrências): Remover o valor do código, ROTACIONAR a credencial (considere-a comprometida, pois permanece no histórico git) e carregar via variável de ambiente/cofre de segredos.
- Média de avaliações retorna NaN para produto sem avaliações: Tratar lista vazia explicitamente antes de dividir.
- Desconto acima de 100% gera preço negativo: Validar 0 ≤ percent ≤ 100 e price ≥ 0, lançando RangeError.
- Dependência 'jsonwebtoken' usada mas não declarada: Declarar a dependência com versão fixada: npm install jsonwebtoken --save (com autorização).
- Teste falhando: media de avaliacoes com lista vazia retorna 0 (2 ocorrências): Investigar a causa raiz; corrigir o código ou o teste (nunca desabilitar).
- Rota sensível sem middleware de autenticação/autorização: Adicionar middleware de autenticação e verificação de papel (RBAC) antes do handler; confirmar se ha proteção global (app.use) antes de classificar como confirmado.
- Possível Path Traversal (caminho de arquivo vindo da requisição): Resolver o caminho com path.resolve e verificar que comeca com o diretório base; usar allowlist.

**P2 — próximo ciclo**

- ruff B006: Replace with `None`; initialize within function
- Exceção genérica capturada/silenciada: Capturar exceções específicas e logar.
- request_without_timeout (B113): https://bandit.readthedocs.io/en/1.9.4/plugins/b113_request_without_timeout.html
- Requisição HTTP sem timeout: Passar timeout=(3.05, 10).
- Coleção em memória 'sessionCache' só cresce (possível vazamento): Usar cache com limite e expiração (LRU com max/ttl) ou armazenamento externo.
- Detalhes internos de erro expostos ao cliente: Logar o erro no servidor e responder mensagem genérica com ID de correlação.
- Endpoint de login sem middleware (rate limit/validação) visível: Adicionar rate limiting (express-rate-limit) e bloqueio progressivo.
- Algoritmo de hash fraco (MD5/SHA-1): Senhas: bcrypt/scrypt/argon2. Integridade: SHA-256+ ou HMAC.
- Dado sensível enviado para log: Remover/mascarar o campo antes de logar.
- Aleatoriedade previsível para valor de segurança: Usar crypto.randomBytes / crypto.randomUUID.
- JWT assinado com segredo literal no código.: Ver mensagem da regra e references/audit-checklist.md.
- JSON.parse sem tratamento de erro: Envolver em try/catch e responder 400 com mensagem clara.
- forEach com callback async (não aguarda as Promises): Usar for...of com await, ou await Promise.all(items.map(async ...)).
- Exceção silenciada (catch vazio): Logar com contexto e propagar ou tratar explicitamente.
- Sessões em memória do processo quebram com múltiplas instâncias: Usar store compartilhado (Redis) com TTL, ou JWT verificado sem estado no servidor.

**P3 — melhoria contínua**

- Dependência vulnerável: cookie (<0.7.0): Atualizar para express@4.22.3
- Dependência vulnerável: send (<0.19.0): Atualizar para express@4.22.3
- Dependência vulnerável: serve-static (<=1.16.0): `npm audit fix` resolve
- blacklist (B403): https://bandit.readthedocs.io/en/1.9.4/blacklists/blacklist_imports.html#b403-import-pickle
- ruff E722: Ajustar conforme a regra.
- SELECT * em consulta (2 ocorrências): Selecionar apenas as colunas necessarias.
- parseInt sem base (radix) e sem validação de NaN: Number.parseInt(v, 10) e validar Number.isNaN / Number.isInteger.
- I/O síncrono (bloqueia o event loop): Usar as versões assíncronas (fs/promises) em código de requisição.
- setInterval sem clearInterval: Guardar o handle e chamar clearInterval no encerramento (ou .unref()).
- Bloco de código duplicado: Extrair função/modulo compartilhado.

---

## CODE INTEGRITY SCORE: 25/100

## NÍVEL DE PROTEÇÃO: CÓDIGO EXPOSTO (Nível 1/5)

<p align="center"><img src="padlock-level-1.png" width="220" alt="Cadeado nível 1 — Código Exposto"></p>

| Critério | Pontos | Confiança | Verificações ausentes |
|---|---|---|---|
| Testes automatizados | 7.9/20 | 100% | - |
| Segurança e vulnerabilidades | 0.0/25 | 100% | - |
| Integridade e lógica | 0.0/20 | 100% | - |
| Estabilidade e tratamento de erros | 7.2/15 | 65% | testes de borda/estresse |
| Performance | 3.0/10 | 35% | testes de carga/benchmark, revisão manual de performance |
| Manutenibilidade | 7.0/10 | 75% | formatação, revisão de arquitetura |

Pontuação bruta: 25.1 · Confiança geral: Alta (86%)

**Tetos aplicados (gates):**

- máx. 59: 9 problema(s) CRÍTICO(s) confirmado(s)
- máx. 74: 2 teste(s) falhando
- máx. 74: cobertura de linhas 12% (< 60%)
- máx. 74: risco CRÍTICO potencial ainda não descartado
- máx. 74: vulnerabilidade ALTA confirmada
- máx. 89: achado(s) de gravidade ALTA em aberto

## Parecer final

| Etapa | Situação | Motivos |
|---|---|---|
| Desenvolvimento | ⚠️ APTO COM RESSALVAS | sempre apto para continuar o desenvolvimento; 1 erro(s) de compilação/tipo bloqueiam partes do código |
| Testes (QA) | ⛔ NÃO APTO | há erros de sintaxe/compilação |
| Homologação | ⛔ NÃO APTO | 9 problema(s) CRÍTICO(s) confirmado(s); 2 teste(s) falhando; CIS 25 < 60 |
| Produção | ⛔ NÃO APTO | 10 achado(s) CRÍTICO(s) em aberto (confirmados ou potenciais); 11 achado(s) de segurança ALTO(s) em aberto; 14 achado(s) ALTO(s) confirmados; suíte de testes não está verde; cobertura 12% < 70%; CIS 25 < 75 |

**Conclusão:** o projeto atingiu **25/100 (Código Exposto)** e está apto, no máximo, para **Desenvolvimento** (com ressalvas). A liberação para produção depende dos critérios de segurança e estabilidade listados, não apenas da nota.

_Este relatório reflete apenas as verificações listadas acima. Ausência de achados não é prova de ausência de vulnerabilidades._
