const db = require("better-sqlite3")("ubuntu.db");

const tables = db.prepare(`
    SELECT name, sql
    FROM sqlite_master
    WHERE type = 'table'
`).all();

console.log(tables);