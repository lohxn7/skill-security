# Testes de estresse, borda e cenários de falha

Objetivo: transformar "isso pode quebrar" em **teste reproduzível** que prova ou descarta o risco.
Regras: ambiente isolado, dados sintéticos, mocks para rede/banco, **nunca produção**. Escreva em
`<projeto>/.code-sentinel/generated-tests/` (mova para o projeto só com autorização).
Caminhos de import partem dessa pasta: `require('../../src/modulo')`.

## Sumário
1. Matriz de cenários
2. Modelos JavaScript (node:test / Jest / Vitest / Supertest)
3. Modelos Python (pytest)
4. Carga leve e memória
5. Registrando o resultado

## 1. Matriz de cenários

Para cada função/rota crítica, percorra:

| Cenário | Entradas/condições |
|---|---|
| Vazio | `''`, `[]`, `{}`, body ausente, arquivo de 0 bytes |
| Nulo | `null`, `undefined`, `None`, campo ausente, header ausente |
| Inesperado | tipo errado (`'1'` vs `1`), `NaN`, `Infinity`, negativo, unicode/emoji, `__proto__`, JSON malformado |
| Limites | 0, 1, máx−1, máx, máx+1, strings de 1 MB, arrays de 10⁶ itens |
| Duplicados | mesmo id duas vezes, requisição repetida (idempotência), chave única violada |
| Concorrência | N requisições simultâneas sobre o mesmo recurso (saldo, estoque, contador) |
| Falha externa | timeout, `ECONNREFUSED`, 500/503, resposta vazia ou parcial, JSON truncado |
| Auth/permissão | sem token, token expirado/forjado, usuário A acessando recurso de B, papel insuficiente |
| Volume/memória | repetir operação 10⁴–10⁵ vezes e medir `heapUsed` |

## 2. Modelos JavaScript

### Função pura — borda e entradas inválidas (node:test)
```js
const test = require('node:test');
const assert = require('node:assert/strict');
const { calculateAverageRating } = require('../../src/pricing');

for (const [entrada, esperado] of [[[], 0], [[5], 5], [[1, 2], 1.5]]) {
  test(`media(${JSON.stringify(entrada)}) = ${esperado}`, () => {
    assert.equal(calculateAverageRating(entrada), esperado);
  });
}
test('media rejeita null com erro claro', () => {
  assert.throws(() => calculateAverageRating(null), TypeError);
});
```

### Rota HTTP — auth, JSON malformado, IDOR (Jest/Vitest + Supertest)
```js
const request = require('supertest');
const app = require('../../src/app'); // exportar app sem chamar listen()

test('sem token -> 401', () => request(app).get('/orders/1').expect(401));
test('JSON malformado -> 400, nao 500', () =>
  request(app).post('/orders').set('Content-Type', 'application/json').send('{"a":').expect(400));
test('usuario A nao le pedido de B (IDOR)', async () => {
  const res = await request(app).get('/orders/ID_DE_B').set('Authorization', `Bearer ${tokenA}`);
  expect([403, 404]).toContain(res.status);
});
```

### Falha de API externa (mock de fetch)
```js
const test = require('node:test');
const assert = require('node:assert/strict');
test('API indisponivel -> erro tratado, sem crash', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw Object.assign(new Error('down'), { code: 'ECONNREFUSED' }); });
  const { getRates } = require('../../src/rates');
  await assert.rejects(getRates(), /indispon|unavailable/i);
});
test('timeout e respeitado', async (t) => {
  t.mock.method(globalThis, 'fetch', (_u, opts) => new Promise((_, rej) =>
    opts?.signal?.addEventListener('abort', () => rej(new Error('aborted')))));
  const { getRates } = require('../../src/rates');
  await assert.rejects(getRates({ timeoutMs: 50 }));
});
```

### Concorrência (condição de corrida)
```js
test('100 compras simultaneas nao vendem alem do estoque', async () => {
  await store.setStock('sku-1', 10);
  const results = await Promise.allSettled(Array.from({ length: 100 }, () => buy('sku-1', 1)));
  const ok = results.filter((r) => r.status === 'fulfilled').length;
  assert.equal(ok, 10);
  assert.equal(await store.getStock('sku-1'), 0);
});
```

## 3. Modelos Python (pytest)

```python
import pytest
from unittest.mock import patch
import requests
from src.legacy.report import fetch_rates

@pytest.mark.parametrize("entrada", ["", None, "a" * 1_000_000, "'; DROP TABLE x;--"])
def test_export_report_entradas_hostis(entrada, fake_cursor):
    ...

def test_api_indisponivel_nao_derruba():
    with patch("requests.get", side_effect=requests.ConnectionError("down")):
        with pytest.raises(requests.ConnectionError):  # ou o erro de dominio esperado
            fetch_rates()

def test_argumento_default_mutavel_nao_vaza_entre_chamadas(fake_cursor):
    a = export_report("a", fake_cursor)
    b = export_report("b", fake_cursor)
    assert b == ["b"]   # falha hoje: ['a', 'b'] -> confirma o bug
```

## 4. Carga leve e memória

Sem ferramenta externa (seguro, local):
```js
test('cache nao cresce sem limite', async () => {
  global.gc?.();
  const before = process.memoryUsage().heapUsed;
  for (let i = 0; i < 50_000; i++) await login(`user${i}`);
  global.gc?.();
  const growthMb = (process.memoryUsage().heapUsed - before) / 1e6;
  assert.ok(growthMb < 20, `heap cresceu ${growthMb.toFixed(1)} MB`);
});
```
Rode com `node --expose-gc --test`. Para carga HTTP real, `autocannon` (Node) ou `k6`/`locust`
**contra ambiente local/staging**, com autorização. Registre `"perf_tests"` em `evidence/manual.json`.

## 5. Registrando o resultado
- Teste falhou e demonstra bug → achado `confirmed` em `findings/manual.json` (com `override: true`
  se já existia como `potential`), `evidence` = nome do teste + mensagem.
- Teste passou → o risco foi descartado para aquele cenário; se era um achado `potential`, registre
  `false_positive` com a justificativa "coberto por teste X".
- Inclua `edge_case_tests` (e `perf_tests`, se aplicável) em `evidence/manual.json` → `checks` somente
  se os testes foram **executados**.
