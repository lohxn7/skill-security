'use strict';

function assertNumbers(values) {
  if (!Array.isArray(values)) {
    throw new TypeError('values deve ser um array');
  }
  for (const v of values) {
    if (typeof v !== 'number' || !Number.isFinite(v)) {
      throw new TypeError('todos os valores devem ser numeros finitos');
    }
  }
}

function mean(values) {
  assertNumbers(values);
  if (values.length === 0) return 0;
  return values.reduce((acc, v) => acc + v, 0) / values.length;
}

function applyDiscount(price, percent) {
  assertNumbers([price, percent]);
  if (price < 0) throw new RangeError('preco negativo');
  if (percent < 0 || percent > 100) throw new RangeError('percentual fora de 0..100');
  return Math.round((price - (price * percent) / 100) * 100) / 100;
}

function parseQuantity(value) {
  const n = Number.parseInt(String(value), 10);
  if (Number.isNaN(n) || n <= 0) throw new RangeError('quantidade invalida');
  return n;
}

module.exports = { mean, applyDiscount, parseQuantity };
