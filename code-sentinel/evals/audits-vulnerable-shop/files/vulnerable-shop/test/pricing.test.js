const test = require('node:test');
const assert = require('node:assert/strict');
const { calculateAverageRating, applyDiscount, parseQuantity, formatPrice } = require('../src/pricing');

test('media de avaliacoes com valores', () => {
  assert.equal(calculateAverageRating([4, 5, 3]), 4);
});

test('media de avaliacoes com lista vazia retorna 0', () => {
  assert.equal(calculateAverageRating([]), 0);
});

test('desconto de 10%', () => {
  assert.equal(applyDiscount(200, 10), 180);
});

test('desconto invalido (acima de 100%) deve lancar erro', () => {
  assert.throws(() => applyDiscount(100, 150), RangeError);
});

test('quantidade numerica', () => {
  assert.equal(parseQuantity('3'), 3);
});

test('formata preco', () => {
  assert.equal(formatPrice(1999), 'R$ 19,99');
});
