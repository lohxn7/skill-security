#!/usr/bin/env python3
"""Análise estática heurística do CODE SENTINEL (JS/TS e Python).

Uso:
    python3 scripts/scan_patterns.py <projeto> [--out DIR]

O que verifica (sem executar código do projeto):
  * padroes de vulnerabilidade (injeção SQL/comando, eval, XSS, TLS desativado,
    path traversal, desserialização insegura, rota administrativa sem middleware...)
  * tratamento de erros (catch vazio, except genérico, JSON.parse sem try,
    requisição HTTP sem timeout, forEach(async))
  * performance (cache/coleção de modulo que só cresce, setInterval sem clear,
    I/O síncrono em handler)
  * manutenibilidade (arquivos muito grandes, funções longas/aninhadas, código duplicado)

TODO achado deste script e heurístico: o status padrão e "potential" (risco potencial),
nunca "confirmed". A confirmação exige leitura do contexto, um teste reproduzível ou
uma ferramenta dedicada (Semgrep/CodeQL/bandit).
Suprima um falso positivo com o comentário `sentinel-ignore` na linha ou na linha anterior.
Saída: <out>/findings/pattern-scan.json e <out>/evidence/pattern-scan.json
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (SOURCE_EXT, finalize_findings, is_test_path, iter_files, out_dir, read_text, rel,  # noqa: E402
                    save_evidence, save_findings)

IGNORE_MARK = "sentinel-ignore"


def _ignored(lines: list[str], ln: int) -> bool:
    """Suprime a linha se o marcador estiver nela ou numa linha ANTERIOR que seja so comentário."""
    if IGNORE_MARK in lines[ln - 1]:
        return True
    if ln > 1:
        prev = lines[ln - 2].strip()
        return IGNORE_MARK in prev and prev.startswith(("//", "#", "/*", "*"))
    return False
REQ = r"(?:req|request|ctx\.request|ctx)\.(?:body|query|params|headers|cookies)"


def R(rule_id, langs, pattern, title, severity, category, description, failure_mode, fix, *,
      fixed_code="", cwe="", owasp="", likelihood="media", impact="", flags=re.I, not_if=None):
    return dict(rule_id=rule_id, langs=langs, rx=re.compile(pattern, flags), title=title, severity=severity,
                category=category, description=description, failure_mode=failure_mode, fix=fix,
                fixed_code=fixed_code, cwe=cwe, owasp=owasp, likelihood=likelihood, impact=impact,
                not_if=re.compile(not_if, re.I) if not_if else None)


JS = ("js", "ts")
PY = ("py",)
RULES = [
    # ---------------------------------------------------------------- segurança
    R("JS-SQL-INJECTION", JS,
      r"(?:query|execute|exec|raw|prepare|all|get|run)\s*\(\s*(?:`[^`]*(?:select|insert|update|delete|where)[^`]*\$\{|"
      r"\"[^\"]*(?:select|insert|update|delete|where)[^\"]*\"\s*\+|'[^']*(?:select|insert|update|delete|where)[^']*'\s*\+)",
      "Possível SQL Injection (consulta montada com concatenação/template)", "CRITICAL", "security",
      "A consulta SQL e construida interpolando valores diretamente na string.",
      "Entrada controlada pelo usuário pode alterar a consulta (ex.: `' OR '1'='1`), ler/alterar/apagar dados.",
      "Usar consultas parametrizadas / placeholders do driver ou query builder.",
      fixed_code="db.query('SELECT * FROM users WHERE id = $1', [userId]);",
      cwe="CWE-89", owasp="A03:2021 Injection", impact="Vazamento ou destruição de dados; bypass de autenticação."),
    R("JS-CMD-INJECTION", JS,
      r"\b(?:exec|execSync|spawnSync|spawn)\s*\(\s*(?:`[^`]*\$\{|[^,)]*\+\s*\w)",
      "Possível Command Injection (comando de shell montado dinamicamente)", "CRITICAL", "security",
      "Um comando de sistema e montado com dados dinamicos.",
      "Metacaracteres (`;`, `&&`, `$()`) na entrada executam comandos arbitrarios no servidor.",
      "Usar execFile/spawn com array de argumentos e shell:false; validar com allowlist.",
      fixed_code="execFile('ping', ['-c', '1', host], { shell: false }, cb);",
      cwe="CWE-78", owasp="A03:2021 Injection", impact="Execução remota de código (RCE)."),
    R("JS-EVAL", JS, r"(?<![\w.])(?:eval\s*\(|new\s+Function\s*\(|set(?:Timeout|Interval)\s*\(\s*['\"`])",
      "Execução dinâmica de código (eval/new Function)", "HIGH", "security",
      "Código e avaliado a partir de string em tempo de execução.",
      "Se a string tiver qualquer parte controlada externamente, ha execução arbitrária de código.",
      "Remover eval; usar JSON.parse, tabelas de despacho ou parsers dedicados.",
      cwe="CWE-95", owasp="A03:2021 Injection", impact="RCE / XSS."),
    R("JS-XSS-SINK", JS, r"\.innerHTML\s*=|\.outerHTML\s*=|dangerouslySetInnerHTML|document\.write\s*\(|insertAdjacentHTML\s*\(",
      "Sink de XSS (HTML inserido sem sanitização)", "HIGH", "security",
      "HTML e injetado diretamente no DOM.",
      "Conteudo controlado pelo usuário executa scripts no navegador de outras pessoas.",
      "Usar textContent / renderização escapada; se HTML for necessário, sanitizar com DOMPurify.",
      fixed_code="el.textContent = userInput;  // ou el.innerHTML = DOMPurify.sanitize(html)",
      cwe="CWE-79", owasp="A03:2021 Injection"),
    R("JS-REFLECTED-XSS", JS, r"res\.(?:send|write|end)\s*\([^)]*(?:`[^`]*\$\{\s*" + REQ + r"|" + REQ + r")",
      "Possível XSS refletido (entrada devolvida na resposta)", "HIGH", "security",
      "Dados da requisição são escritos diretamente na resposta HTTP.",
      "Um link malicioso faz o servidor devolver script que executa no navegador da vitima.",
      "Escapar a saída ou responder JSON (res.json) com Content-Type correto.",
      cwe="CWE-79", owasp="A03:2021 Injection"),
    R("JS-PATH-TRAVERSAL", JS,
      r"(?:readFile|readFileSync|createReadStream|sendFile|download|unlink|writeFile|writeFileSync)\s*\([^)]*" + REQ,
      "Possível Path Traversal (caminho de arquivo vindo da requisição)", "HIGH", "security",
      "Um caminho de arquivo e derivado de entrada do usuário.",
      "`../../etc/passwd` permite ler/escrever arquivos fora do diretório esperado.",
      "Resolver o caminho com path.resolve e verificar que comeca com o diretório base; usar allowlist.",
      fixed_code="const p = path.resolve(BASE, name);\nif (!p.startsWith(BASE + path.sep)) return res.sendStatus(400);",
      cwe="CWE-22", owasp="A01:2021 Broken Access Control"),
    R("JS-OPEN-REDIRECT", JS, r"res\.redirect\s*\([^)]*" + REQ,
      "Possível Open Redirect", "MEDIUM", "security",
      "O destino do redirecionamento vem da requisição.",
      "Atacantes usam o dominio confiável para redirecionar vitimas a sites de phishing.",
      "Aceitar apenas caminhos relativos ou destinos de uma allowlist.", cwe="CWE-601", owasp="A01:2021"),
    R("JS-ADMIN-ROUTE-NO-AUTH", JS,
      r"\b(?:app|router)\.(?:get|post|put|patch|delete|all)\s*\(\s*['\"`][^'\"`]*(?:admin|internal|debug|manage|reset|delete)"
      r"[^'\"`]*['\"`]\s*,\s*(?:async\s*)?(?:function\s*)?\(?\s*(?:req|request)\b",
      "Rota sensível sem middleware de autenticação/autorização", "HIGH", "security",
      "Rota administrativa/sensível registrada com o handler direto, sem middleware de auth visível.",
      "Qualquer cliente anonimo pode invocar a operação privilegiada.",
      "Adicionar middleware de autenticação e verificação de papel (RBAC) antes do handler; confirmar se ha "
      "proteção global (app.use) antes de classificar como confirmado.",
      fixed_code="app.delete('/admin/users/:id', requireAuth, requireRole('admin'), handler);",
      cwe="CWE-862", owasp="A01:2021 Broken Access Control / ASVS V4", likelihood="alta"),
    R("JS-JWT-DECODE-NO-VERIFY", JS, r"\bjwt\.decode\s*\(",
      "JWT decodificado sem verificação de assinatura", "HIGH", "security",
      "jwt.decode não valida assinatura nem expiração.",
      "Tokens forjados são aceitos se o resultado for usado para autorização.",
      "Usar jwt.verify(token, secret, { algorithms: ['HS256'] }).", cwe="CWE-347", owasp="A07:2021"),
    R("JS-JWT-ALG-NONE", JS, r"algorithms?\s*:\s*\[?\s*['\"]none['\"]",
      "JWT aceita algoritmo 'none'", "CRITICAL", "security", "Configuração aceita tokens sem assinatura.",
      "Qualquer um pode forjar tokens validos.", "Fixar algoritmos seguros (HS256/RS256).",
      cwe="CWE-347", owasp="A02:2021"),
    R("JS-TLS-DISABLED", JS, r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
      "Verificação de certificado TLS desativada", "HIGH", "security",
      "Conexoes TLS aceitam qualquer certificado.", "Permite ataques man-in-the-middle.",
      "Remover a opção; configurar a CA correta (ca: fs.readFileSync(...)).", cwe="CWE-295", owasp="A02:2021"),
    R("JS-WEAK-HASH", JS, r"createHash\s*\(\s*['\"](?:md5|sha1)['\"]",
      "Algoritmo de hash fraco (MD5/SHA-1)", "MEDIUM", "security",
      "MD5/SHA-1 são inadequados para senhas e integridade.",
      "Senhas com hash rápido são quebradas por força bruta; colisoes possibilitam falsificação.",
      "Senhas: bcrypt/scrypt/argon2. Integridade: SHA-256+ ou HMAC.",
      fixed_code="const hash = await bcrypt.hash(password, 12);", cwe="CWE-327", owasp="A02:2021"),
    R("JS-INSECURE-RANDOM", JS, r"Math\.random\s*\(\).{0,60}(?:token|secret|password|session|otp|nonce|salt|key)|"
                                r"(?:token|secret|password|session|otp|nonce|salt)\w*\s*[:=].{0,40}Math\.random\s*\(",
      "Aleatoriedade previsível para valor de segurança", "MEDIUM", "security",
      "Math.random não e criptograficamente seguro.", "Tokens/IDs de sessão podem ser previstos.",
      "Usar crypto.randomBytes / crypto.randomUUID.", cwe="CWE-338", owasp="A02:2021"),
    R("JS-CORS-WILDCARD", JS, r"origin\s*:\s*['\"]\*['\"]|Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*|\bcors\s*\(\s*\)",
      "CORS liberado para qualquer origem", "MEDIUM", "security",
      "Qualquer site pode chamar a API a partir do navegador.",
      "Combinado com credenciais/cookies, permite que sites terceiros leiam dados do usuário.",
      "Restringir origin a uma allowlist de dominios.", cwe="CWE-942", owasp="A05:2021"),
    R("JS-PROTOTYPE-POLLUTION", JS, r"(?:Object\.assign|_\.merge|_\.defaultsDeep|\bmerge|\bextend)\s*\([^)]*" + REQ,
      "Possível Prototype Pollution / mass assignment", "MEDIUM", "security",
      "Objeto da requisição e mesclado diretamente em outro objeto.",
      "`__proto__`/`constructor` ou campos como `isAdmin` podem ser injetados.",
      "Selecionar campos permitidos explicitamente (allowlist) e validar com schema (zod/joi).",
      cwe="CWE-1321", owasp="A08:2021"),
    R("JS-STACK-LEAK", JS, r"res\.(?:send|json|status\([^)]*\)\.(?:send|json))\s*\([^)]*(?:err|error|e)\.(?:stack|message)",
      "Detalhes internos de erro expostos ao cliente", "MEDIUM", "security",
      "Mensagens/stack traces de exceções são devolvidas na resposta.",
      "Revela estrutura interna, consultas SQL e caminhos, facilitando ataques.",
      "Logar o erro no servidor e responder mensagem genérica com ID de correlação.", cwe="CWE-209", owasp="A05:2021"),
    R("JS-SENSITIVE-LOG", JS, r"console\.(?:log|info|debug)\s*\([^)]*(?:password|senha|token|secret|authorization|cpf|card)",
      "Dado sensível enviado para log", "MEDIUM", "security",
      "Valores sensíveis são registrados em log.", "Logs são copiados para varios sistemas e pessoas.",
      "Remover/mascarar o campo antes de logar.", cwe="CWE-532", owasp="A09:2021"),
    R("JS-NO-RATE-LIMIT-LOGIN", JS, r"\b(?:app|router)\.post\s*\(\s*['\"`][^'\"`]*(?:login|signin|auth|token)[^'\"`]*['\"`]\s*,\s*(?:async\s*)?\(?\s*(?:req|request)\b",
      "Endpoint de login sem middleware (rate limit/validação) visível", "MEDIUM", "security",
      "Rota de autenticação recebe o handler diretamente.",
      "Sem limite de tentativas, permite força bruta e credential stuffing.",
      "Adicionar rate limiting (express-rate-limit) e bloqueio progressivo.", cwe="CWE-307", owasp="A07:2021"),

    R("PY-SQL-INJECTION", PY,
      r"\.execute(?:many)?\s*\(\s*(?:f['\"]|['\"][^'\"]*['\"]\s*(?:%|\+|\.format))",
      "Possível SQL Injection (consulta formatada)", "CRITICAL", "security",
      "A consulta SQL e construida com f-string/format/concatenação.",
      "Entrada maliciosa altera a consulta.", "Usar parametros do driver: cursor.execute(sql, (valor,)).",
      fixed_code='cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))', cwe="CWE-89", owasp="A03:2021"),
    R("PY-SHELL", PY, r"shell\s*=\s*True|\bos\.system\s*\(|\bos\.popen\s*\(|subprocess\.getoutput\s*\(",
      "Execução de comando via shell", "HIGH", "security", "Comando executado através do shell.",
      "Dados dinamicos no comando permitem injeção de comandos.",
      "subprocess.run([...], shell=False) com lista de argumentos.", cwe="CWE-78", owasp="A03:2021"),
    R("PY-EVAL", PY, r"(?<![\w.])(?:eval|exec)\s*\(", "Execução dinâmica de código (eval/exec)", "HIGH", "security",
      "Código Python avaliado a partir de string.", "Entrada controlada externamente vira RCE.",
      "Usar ast.literal_eval ou parsing explicito.", cwe="CWE-95", owasp="A03:2021"),
    R("PY-UNSAFE-DESERIALIZATION", PY, r"\bpickle\.loads?\s*\(|\bmarshal\.loads?\s*\(|\byaml\.load\s*\((?![^)]*SafeLoader)|"
                                       r"\byaml\.unsafe_load\s*\(",
      "Desserialização insegura", "HIGH", "security", "Dados são desserializados com formato que executa código.",
      "Um payload malicioso executa código arbitrário durante a desserialização.",
      "Usar json ou yaml.safe_load; nunca desserializar pickle de fonte não confiável.",
      cwe="CWE-502", owasp="A08:2021"),
    R("PY-TLS-DISABLED", PY, r"verify\s*=\s*False", "Verificação TLS desativada", "HIGH", "security",
      "Requisições HTTPS aceitam qualquer certificado.", "Permite man-in-the-middle.",
      "Remover verify=False; apontar o bundle de CA correto.", cwe="CWE-295", owasp="A02:2021"),
    R("PY-DEBUG-ENABLED", PY, r"^\s*DEBUG\s*=\s*True|\.run\s*\([^)]*debug\s*=\s*True",
      "Modo debug habilitado", "HIGH", "security", "Aplicação configurada com debug ativo.",
      "Em produção, o debugger do Flask/Werkzeug permite execução de código; Django expoe configurações.",
      "Ler DEBUG de variável de ambiente, padrão False.", cwe="CWE-489", owasp="A05:2021"),
    R("PY-WEAK-HASH", PY, r"hashlib\.(?:md5|sha1)\s*\(", "Algoritmo de hash fraco (MD5/SHA-1)", "MEDIUM", "security",
      "Hash fraco em uso.", "Senhas quebráveis/colisoes.", "Usar argon2/bcrypt para senhas; sha256 para integridade.",
      cwe="CWE-327", owasp="A02:2021"),

    # ---------------------------------------------------------- estabilidade
    R("JS-EMPTY-CATCH", JS, r"catch\s*(?:\(\s*[\w{}\s,]*\))?\s*\{\s*(?://[^\n]*)?\}",
      "Exceção silenciada (catch vazio)", "MEDIUM", "stability",
      "O erro e capturado e descartado sem log nem tratamento.",
      "Falhas reais passam despercebidas; o sistema continua em estado inconsistente.",
      "Logar com contexto e propagar ou tratar explicitamente.",
      fixed_code="catch (err) {\n  logger.error({ err }, 'falha ao processar X');\n  throw err;\n}", cwe="CWE-390"),
    R("JS-PROMISE-NO-CATCH-EMPTY", JS, r"\.catch\s*\(\s*\(\s*\w*\s*\)\s*=>\s*\{\s*\}\s*\)|\.catch\s*\(\s*\(\)\s*=>\s*(?:null|undefined)\s*\)",
      "Rejeição de Promise silenciada", "MEDIUM", "stability", "Erros assíncronos são descartados.",
      "Operações falham sem sinal; dados podem ficar parcialmente gravados.",
      "Tratar ou propagar o erro; ao menos logar.", cwe="CWE-390"),
    R("JS-FOREACH-ASYNC", JS, r"\.forEach\s*\(\s*async\b",
      "forEach com callback async (não aguarda as Promises)", "MEDIUM", "integrity",
      "Array.forEach ignora as Promises retornadas.",
      "O código seguinte executa antes do fim das operações; erros viram unhandledRejection.",
      "Usar for...of com await, ou await Promise.all(items.map(async ...)).",
      fixed_code="for (const item of items) {\n  await process(item);\n}", likelihood="alta"),
    R("JS-PARSEINT-NO-RADIX", JS, r"parseInt\s*\(\s*[^,()]+\)", "parseInt sem base (radix) e sem validação de NaN",
      "LOW", "integrity", "parseInt sem radix/validação pode devolver NaN ou valor inesperado.",
      "NaN se propaga silenciosamente em calculos e consultas.",
      "Number.parseInt(v, 10) e validar Number.isNaN / Number.isInteger.", likelihood="media"),
    R("JS-HTTP-NO-TIMEOUT", JS, r"\b(?:fetch|axios(?:\.(?:get|post|put|delete|patch))?)\s*\((?![^)]*(?:timeout|signal))[^)]*\)\s*;?\s*$",
      "Chamada HTTP externa sem timeout", "LOW", "stability",
      "A chamada não define timeout/AbortSignal.",
      "Se a API externa travar, requisições se acumulam e esgotam recursos.",
      "fetch(url, { signal: AbortSignal.timeout(5000) }) / axios({ timeout: 5000 }).", likelihood="media"),
    R("PY-BARE-EXCEPT", PY, r"^\s*except\s*:\s*(?:#.*)?$|^\s*except\s+(?:Exception|BaseException)\s*(?:as\s+\w+)?\s*:\s*pass\b",
      "Exceção genérica capturada/silenciada", "MEDIUM", "stability",
      "`except:` / `except Exception: pass` engole qualquer erro (inclusive KeyboardInterrupt no bare except).",
      "Erros reais desaparecem; estado inconsistente; depuração muito difícil.",
      "Capturar exceções específicas e logar.", cwe="CWE-396"),
    R("PY-REQUESTS-NO-TIMEOUT", PY, r"\brequests\.(?:get|post|put|delete|patch|head|request)\s*\((?![^)]*timeout)",
      "Requisição HTTP sem timeout", "MEDIUM", "stability",
      "requests sem timeout espera indefinidamente.", "Workers ficam presos se o serviço remoto travar.",
      "Passar timeout=(3.05, 10).", cwe="CWE-400"),
    R("PY-MUTABLE-DEFAULT", PY, r"def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\)|list\(\)|dict\(\))",
      "Argumento padrão mutável", "MEDIUM", "integrity",
      "O valor padrão mutável e compartilhado entre chamadas.",
      "Dados de uma chamada vazam para a proxima (bug intermitente).",
      "Usar None como padrão e criar o objeto dentro da função.",
      fixed_code="def f(items=None):\n    items = [] if items is None else items", likelihood="alta"),

    # ----------------------------------------------------------- performance
    R("JS-SYNC-IO", JS, r"\b(?:readFileSync|writeFileSync|execSync|readdirSync|statSync)\s*\(",
      "I/O síncrono (bloqueia o event loop)", "LOW", "performance",
      "Chamada sincrona bloqueia o processo Node inteiro enquanto executa.",
      "Sob carga, todas as requisições concorrentes ficam paradas aguardando.",
      "Usar as versões assíncronas (fs/promises) em código de requisição.", likelihood="media"),
    R("GEN-SELECT-STAR", JS + PY, r"select\s+\*\s+from", "SELECT * em consulta", "LOW", "performance",
      "Consulta traz todas as colunas.", "Trafega dados desnecessarios/sensíveis; quebra com mudancas de schema.",
      "Selecionar apenas as colunas necessarias.", likelihood="baixa"),

    # ------------------------------------------------------- manutenibilidade
    R("GEN-TODO", JS + PY, r"(?://|#)\s*(?:TODO|FIXME|HACK|XXX)\b", "Marcador TODO/FIXME pendente", "INFO",
      "maintainability", "Trabalho pendente marcado no código.", "Indica comportamento incompleto conhecido.",
      "Converter em issue rastreável ou resolver.", flags=0),
]


def _strip_line_comment(line: str, lang: str) -> str:
    s = line.lstrip()
    if lang in JS and (s.startswith("//") or s.startswith("*") or s.startswith("/*")):
        return ""
    if lang in PY and s.startswith("#"):
        return ""
    return line


def file_level_checks(r: str, lang: str, text: str, lines: list[str]) -> list[dict]:
    out = []
    n = len(lines)
    if n > 600:
        out.append(dict(rule_id="GEN-LARGE-FILE", title=f"Arquivo muito grande ({n} linhas)", severity="LOW",
                        category="maintainability", file=r, line=1,
                        description="Arquivo concentra muitas responsabilidades.",
                        failure_mode="Mudancas tem alto risco de regressão; difícil testar isoladamente.",
                        fix="Extrair modulos coesos por responsabilidade.", likelihood="media"))
    if lang in JS:
        # coleção de modulo que só cresce -> possível vazamento de memória
        for m in re.finditer(r"^(?:const|let|var)\s+(\w+)\s*=\s*(?:\{\s*\}|\[\s*\]|new\s+(?:Map|Set)\s*\(\s*\))\s*;?",
                             text, re.M):
            name = m.group(1)
            grows = re.search(rf"\b{name}(?:\.push\s*\(|\.set\s*\(|\.add\s*\(|\[[^\]]+\]\s*=(?!=))", text)
            shrinks = re.search(rf"\b{name}(?:\.delete\s*\(|\.clear\s*\(|\.splice\s*\(|\.shift\s*\(|\.pop\s*\(|"
                                rf"\.length\s*=|\s*=\s*(?:\{{|\[|new))|delete\s+{name}\[", text[m.end():])
            if grows and not shrinks:
                ln = text[:m.start()].count("\n") + 1
                out.append(dict(
                    rule_id="JS-UNBOUNDED-COLLECTION", title=f"Coleção em memória '{name}' só cresce (possível vazamento)",
                    severity="MEDIUM", category="performance", file=r, line=ln,
                    description=f"'{name}' e um objeto/array/Map no escopo do modulo que recebe itens e nunca e limpo.",
                    failure_mode="Em processo de longa duração a memória cresce a cada requisição até o OOM/crash.",
                    fix="Usar cache com limite e expiração (LRU com max/ttl) ou armazenamento externo.",
                    fixed_code="const { LRUCache } = require('lru-cache');\nconst cache = new LRUCache({ max: 1000, ttl: 60_000 });",
                    cwe="CWE-401", likelihood="alta", impact="Degradação progressiva e queda do serviço."))
        if re.search(r"\bsetInterval\s*\(", text) and not re.search(r"\bclearInterval\s*\(", text):
            ln = next((i for i, l in enumerate(lines, 1) if "setInterval" in l), 1)
            out.append(dict(rule_id="JS-INTERVAL-NO-CLEAR", title="setInterval sem clearInterval", severity="LOW",
                            category="performance", file=r, line=ln,
                            description="Timer recorrente nunca e cancelado.",
                            failure_mode="Impede shutdown limpo, mantem referências vivas e vaza em testes.",
                            fix="Guardar o handle e chamar clearInterval no encerramento (ou .unref()).",
                            likelihood="media"))
        # JSON.parse sem try por perto
        for i, l in enumerate(lines):
            if "JSON.parse(" in l and IGNORE_MARK not in l:
                window = "\n".join(lines[max(0, i - 6):i + 1])
                if not re.search(r"\btry\b|\.catch\b|safeParse", window):
                    out.append(dict(rule_id="JS-JSON-PARSE-UNGUARDED", title="JSON.parse sem tratamento de erro",
                                    severity="MEDIUM", category="stability", file=r, line=i + 1,
                                    description="JSON.parse lanca SyntaxError com entrada inválida/vazia.",
                                    failure_mode="Payload malformado derruba a requisição (500) ou o processo, se fora de handler.",
                                    fix="Envolver em try/catch e responder 400 com mensagem clara.",
                                    fixed_code="let data;\ntry { data = JSON.parse(raw); }\ncatch { return res.status(400).json({ error: 'JSON inválido' }); }",
                                    likelihood="alta", cwe="CWE-20"))
        # divisão por variável sem verificação de zero (heurística bem conservadora)
        for i, l in enumerate(lines):
            m = re.search(r"[\w)\]]\s*/\s*([a-zA-Z_][\w.]*(?:\.length)?)\s*[;,)]", l)
            if m and not l.lstrip().startswith(("//", "*", "import", "require")) and "://" not in l:
                var = m.group(1)
                ctx = "\n".join(lines[max(0, i - 4):i + 1])
                if re.search(rf"{re.escape(var)}\s*(?:===?|!==?|>|<=?)\s*0|!\s*{re.escape(var)}\b|{re.escape(var)}\s*\|\|", ctx):
                    continue
                if var.endswith(".length") or re.search(r"count|total|len|size|qty|quantity|n\b", var, re.I):
                    out.append(dict(rule_id="JS-DIV-BY-ZERO", title=f"Divisão por '{var}' sem verificar zero",
                                    severity="MEDIUM", category="integrity", file=r, line=i + 1,
                                    description="Divisor pode ser 0 (lista vazia/contagem zero).",
                                    failure_mode="Resulta em NaN/Infinity que se propaga para respostas, banco ou UI.",
                                    fix="Tratar o caso vazio explicitamente antes de dividir.",
                                    fixed_code=f"if ({var} === 0) return 0; // ou lancar erro de dominio",
                                    likelihood="media", cwe="CWE-369"))
    # funções longas / aninhamento profundo (aproximação por indentação)
    deep = 0
    for i, l in enumerate(lines, 1):
        stripped = l.rstrip()
        if not stripped:
            continue
        indent = len(l) - len(l.lstrip(" \t").replace("\t", "    "))
        level = indent // (4 if lang in PY else 2)
        if level >= (6 if lang in PY else 8) and deep == 0:
            deep = i
    if deep:
        out.append(dict(rule_id="GEN-DEEP-NESTING", title="Aninhamento profundo de blocos", severity="LOW",
                        category="maintainability", file=r, line=deep,
                        description="Blocos muito aninhados indicam alta complexidade ciclomática.",
                        failure_mode="Caminhos de execução dificeis de testar; bugs de borda escondidos.",
                        fix="Extrair funções, usar early-return/guard clauses.", likelihood="media"))
    return out


def duplication(blocks: dict[str, list[tuple[str, int]]]) -> list[dict]:
    out, seen_pairs = [], set()
    for h, locs in blocks.items():
        uniq = []
        for f, ln in locs:
            if all(not (f == g and abs(ln - m) < 8) for g, m in uniq):
                uniq.append((f, ln))
        if len(uniq) < 2:
            continue
        key = tuple(sorted({f for f, _ in uniq}))
        if key in seen_pairs:
            continue
        seen_pairs.add(key)
        (f1, l1), (f2, l2) = uniq[0], uniq[1]
        out.append(dict(rule_id="GEN-DUPLICATE-CODE", title="Bloco de código duplicado", severity="LOW",
                        category="maintainability", file=f1, line=l1,
                        description=f"Bloco de 8+ linhas idêntico em {f2}:{l2}" +
                                    (f" (+{len(uniq) - 2} ocorrências)" if len(uniq) > 2 else "") + ".",
                        failure_mode="Correções aplicadas em uma copia e esquecidas na outra geram comportamento divergente.",
                        fix="Extrair função/modulo compartilhado.", likelihood="media"))
    return out


NODE_BUILTINS = set("""assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel dns
domain events fs http http2 https inspector module net os path perf_hooks process punycode querystring readline repl
stream string_decoder sys timers tls trace_events tty url util v8 vm wasi worker_threads zlib test""".split())
IMPORT_RE = re.compile(r"""(?:require\s*\(\s*|import\s*\(\s*|\bfrom\s+|^\s*import\s+)['"]([^'"./][^'"]*)['"]""", re.M)


def undeclared_deps(project: Path, r: str, text: str, declared: set[str] | None) -> list[dict]:
    """Pacote importado que não esta no package.json: quebra em instalação limpa (npm ci)."""
    if declared is None:
        return []
    out, seen = [], set()
    for m in IMPORT_RE.finditer(text):
        spec = m.group(1)
        if spec.startswith("node:"):
            continue
        name = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
        if name in NODE_BUILTINS or name in declared or name in seen:
            continue
        seen.add(name)
        ln = text[:m.start()].count("\n") + 1
        out.append(dict(rule_id="JS-UNDECLARED-DEPENDENCY", title=f"Dependência '{name}' usada mas não declarada",
                        severity="HIGH", status="confirmed", category="integrity", file=r, line=ln,
                        description=f"'{name}' e importado, mas não consta em dependencies/devDependencies do package.json.",
                        failure_mode="Em uma instalação limpa (npm ci, deploy, CI) o require falha com "
                                     "MODULE_NOT_FOUND e o processo não sobe; hoje so funciona por acaso "
                                     "(pacote transitivo ou instalado globalmente).",
                        likelihood="alta", impact="Falha de deploy / indisponibilidade.",
                        fix=f"Declarar a dependência com versão fixada: npm install {name} --save (com autorização).",
                        source="pattern-scan"))
    return out


def scan(project: Path) -> tuple[list[dict], dict]:
    findings: list[dict] = []
    blocks: dict[str, list[tuple[str, int]]] = defaultdict(list)
    files = 0
    langs_seen = set()
    declared = None
    pkg_path = project / "package.json"
    if pkg_path.exists():
        import json
        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
            declared = set()
            for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                declared |= set((pkg.get(k) or {}).keys())
            declared.add(pkg.get("name", ""))
        except (OSError, ValueError):
            declared = None
    for p in iter_files(project):
        lang = SOURCE_EXT.get(p.suffix.lower())
        if lang not in ("js", "ts", "py") or p.name.endswith(".min.js"):
            continue
        text = read_text(p)
        if text is None:
            continue
        files += 1
        langs_seen.add(lang)
        r = rel(project, p)
        in_test = is_test_path(r)
        lines = text.splitlines()
        for ln, line in enumerate(lines, 1):
            if _ignored(lines, ln):
                continue
            code = _strip_line_comment(line, lang)
            if not code and "TODO" not in line and "FIXME" not in line:
                continue
            for rule in RULES:
                if lang not in rule["langs"]:
                    continue
                target = line if rule["rule_id"] == "GEN-TODO" else code
                if not target or not rule["rx"].search(target):
                    continue
                if rule["not_if"] and rule["not_if"].search(target):
                    continue
                findings.append(_mk(rule, r, ln, line, in_test))
        if lang in JS and not in_test:
            for f in undeclared_deps(project, r, text, declared):
                if IGNORE_MARK not in lines[f["line"] - 1]:
                    f.update(in_test_code=False, evidence=lines[f["line"] - 1].strip()[:200])
                    findings.append(f)
        for f in file_level_checks(r, lang, text, lines):
            if IGNORE_MARK in (lines[f["line"] - 1] if 0 < f["line"] <= len(lines) else ""):
                continue
            f.update(status="potential", source="pattern-scan", in_test_code=in_test,
                     evidence=(lines[f["line"] - 1].strip()[:200] if 0 < f["line"] <= len(lines) else ""))
            if in_test:
                f["severity"] = _downgrade(f["severity"])
            findings.append(f)
        if not in_test:
            norm = [re.sub(r"\s+", " ", l.strip()) for l in lines]
            for i in range(0, max(0, len(norm) - 8)):
                win = norm[i:i + 8]
                meaningful = [w for w in win if len(w) > 3 and w not in ("});", "}", "})", "];", "end")]
                if len(meaningful) < 7:
                    continue
                blocks[hashlib.sha1("\n".join(win).encode()).hexdigest()].append((r, i + 1))
    for f in duplication(blocks):
        f.update(status="potential", source="pattern-scan", in_test_code=False)
        findings.append(f)
    checks = ["sast_heuristic", "error_handling_heuristic", "perf_heuristic", "duplication", "complexity_heuristic"]
    ev = {"tool": "scan_patterns.py", "version": "1.0", "status": "executed", "checks": checks,
          "files_scanned": files, "languages": sorted(langs_seen), "rules": len(RULES) + 7}
    return finalize_findings(findings, "PAT"), ev


def _downgrade(sev: str) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    return order[min(len(order) - 1, order.index(sev) + 2)]


def _mk(rule: dict, r: str, ln: int, line: str, in_test: bool) -> dict:
    sev = _downgrade(rule["severity"]) if in_test and rule["category"] == "security" else rule["severity"]
    return {
        "rule_id": rule["rule_id"], "title": rule["title"], "severity": sev, "status": "potential",
        "category": rule["category"], "file": r, "line": ln,
        "description": rule["description"], "failure_mode": rule["failure_mode"],
        "likelihood": rule["likelihood"], "impact": rule["impact"] or rule["failure_mode"],
        "fix": rule["fix"], "fixed_code": rule["fixed_code"], "source": "pattern-scan",
        "evidence": line.strip()[:240], "cwe": rule["cwe"], "owasp": rule["owasp"], "in_test_code": in_test,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    ap.add_argument("--out")
    a = ap.parse_args()
    project = Path(a.project)
    d = out_dir(project, a.out)
    findings, ev = scan(project)
    ev["findings"] = len(findings)
    save_findings(d, "pattern-scan", findings)
    save_evidence(d, "pattern-scan", ev)
    print(f"[patterns] {ev['files_scanned']} arquivos, {len(findings)} achados -> {d / 'findings' / 'pattern-scan.json'}")


if __name__ == "__main__":
    main()
