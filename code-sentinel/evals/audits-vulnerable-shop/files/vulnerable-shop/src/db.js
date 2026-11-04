// FIXTURE: "banco" em memoria com credencial hardcoded.
const DATABASE_URL = 'postgres://admin:Sup3rS3cretPw@db.internal:5432/shop';

const users = [{ id: 1, name: 'ana', passwordHash: '5f4dcc3b5aa765d61d8327deb882cf99' }];

module.exports = {
  url: DATABASE_URL,
  query(sql, cb) { cb(null, users.filter((u) => sql.includes(u.name))); },
  findUser(name) { return users.find((u) => u.name === name); },
  remove(id) { const i = users.findIndex((u) => u.id === Number(id)); if (i >= 0) users.splice(i, 1); },
  ratingsFor() { return []; },
  sendMail() { return Promise.resolve(); },
  cleanup() {},
};
