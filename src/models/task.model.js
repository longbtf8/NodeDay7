const pool = require("@/config/database");
const findAll = async () => {
  try {
    const [rows] = await pool.query(
      "SELECT * FROM tasks ORDER BY created_at DESC;",
    );
    return rows;
  } catch (error) {
    console.log(error);
  }
};

const findOne = async (id) => {
  try {
    const [rows] = await pool.query(`SELECT * FROM tasks WHERE id = ?;`, [id]);
    return rows[0];
  } catch (error) {
    console.log(error);
  }
};
const create = async (taskData) => {
  try {
    const title = taskData;
    const [rows] = await pool.query(`INSERT INTO tasks (title) VALUES (?)`, [
      title,
    ]);

    if (rows) {
      return true;
    }
  } catch (error) {
    return false;
  }
};
const update = async (id, taskData) => {
  try {
    const title = taskData;
    const [rows] = await pool.query(
      `UPDATE tasks SET title = '${title}' WHERE id = ?`,
      [id],
    );
    console.log(rows);

    if (rows) {
      return true;
    }
  } catch (error) {
    console.log(error);
    return false;
  }
};
const destroy = async (id) => {
  try {
    const [rows] = await pool.query(`DELETE FROM tasks WHERE id = ?`, [id]);
    console.log(rows);

    if (rows) {
      return true;
    }
  } catch (error) {
    console.log(error);
    return false;
  }
};
module.exports = { findAll, findOne, create, update, destroy };
