'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { mean, applyDiscount, parseQuantity } = require('../src/stats');

test('mean de valores', () => assert.equal(mean([1, 2, 3]), 2));
test('mean de lista vazia retorna 0', () => assert.equal(mean([]), 0));
test('mean rejeita entrada invalida (null, NaN, string)', () => {
  assert.throws(() => mean(null), TypeError);
  assert.throws(() => mean([1, NaN]), TypeError);
  assert.throws(() => mean(['1']), TypeError);
});
test('mean com grande volume de dados (limite de 1e6 itens)', () => {
  const big = Array.from({ length: 1_000_000 }, () => 1);
  assert.equal(mean(big), 1);
});
test('applyDiscount normal e limites 0/100', () => {
  assert.equal(applyDiscount(200, 10), 180);
  assert.equal(applyDiscount(200, 0), 200);
  assert.equal(applyDiscount(200, 100), 0);
});
test('applyDiscount rejeita percentual invalido e preco negativo', () => {
  assert.throws(() => applyDiscount(100, 150), RangeError);
  assert.throws(() => applyDiscount(100, -1), RangeError);
  assert.throws(() => applyDiscount(-5, 10), RangeError);
});
test('parseQuantity valida entrada', () => {
  assert.equal(parseQuantity('3'), 3);
  assert.throws(() => parseQuantity(''), RangeError);
  assert.throws(() => parseQuantity('abc'), RangeError);
  assert.throws(() => parseQuantity(0), RangeError);
});
test('chamadas concorrentes sao independentes (Promise.all)', async () => {
  const r = await Promise.all([1, 2, 3].map(async (n) => mean([n, n])));
  assert.deepEqual(r, [1, 2, 3]);
});
