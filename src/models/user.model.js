const db = require("@/config/database");

const findAll = async (limit, offset, condition = {}) => {
  const queryStr = Object.entries(condition)
    .filter(([_, value]) => value !== undefined)
    .map(([key, value]) => {
      value = typeof value === "number" ? value : `"${value}"`;
      return `${key}=${value}`;
    })
    .join(" and ");
  try {
    const [rows] = await db.query(
      `Select * from users ${queryStr ? `where ${queryStr}` : ""} LIMIT ? offset ?`,
      [Number(limit), Number(offset)],
    );
    return rows;
  } catch (error) {
    console.log(error);
  }
};
const count = async () => {
  try {
    const [rows] = await db.query(`Select count(*)as count from users`);
    return rows[0].count;
  } catch (error) {
    console.log(error);
  }
};
const findAsEmail = async (email) => {
  try {
    const [rows] = await db.query(`Select * from users where email like ?`, [
      `%${email}%`,
    ]);
    return rows;
  } catch (error) {
    console.log(error);
  }
};

module.exports = { findAll, count, findAsEmail };
