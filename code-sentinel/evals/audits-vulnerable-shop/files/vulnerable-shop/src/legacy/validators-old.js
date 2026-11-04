// copia antiga mantida "por garantia" (duplicacao intencional)
function validateLegacyOrder(order) {
  if (!order) throw new Error('pedido ausente');
  if (!Array.isArray(order.items)) throw new Error('itens invalidos');
  if (order.items.length === 0) throw new Error('pedido vazio');
  for (const item of order.items) {
    if (typeof item.sku !== 'string') throw new Error('sku invalido');
    if (!Number.isInteger(item.qty) || item.qty <= 0) throw new Error('quantidade invalida');
    if (typeof item.price !== 'number' || item.price < 0) throw new Error('preco invalido');
  }
  return true;
}
module.exports = { validateLegacyOrder };
