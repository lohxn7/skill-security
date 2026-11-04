// FIXTURE: funcoes puras com bugs de logica intencionais.

function calculateAverageRating(ratings) {
  const total = ratings.reduce((sum, r) => sum + r, 0);
  return total / ratings.length;
}

function applyDiscount(price, percent) {
  return price - (price * percent) / 100;
}

function parseQuantity(value) {
  return parseInt(value);
}

function formatPrice(cents) {
  return `R$ ${(cents / 100).toFixed(2).replace('.', ',')}`;
}

module.exports = { calculateAverageRating, applyDiscount, parseQuantity, formatPrice };
