const taskModel = require("@/models/task.model");

const findAll = async (req, res) => {
  try {
    const rows = await taskModel.findAll();

    res.success(rows);
  } catch (error) {
    res.error(404, ((message = "Resource not found"), error));
  }
};
const findOne = async (req, res) => {
  try {
    const { id } = req.params;
    const row = await taskModel.findOne(id);

    if (row) {
      res.success(row);
    } else {
      res.error(404, ((message = "Resource not found"), error));
    }
  } catch (error) {
    res.error(404, ((message = "Resource not found"), error));
  }
};
const create = async (req, res) => {
  try {
    const { title } = req.body;
    console.log(title);
    const row = await taskModel.create(title);
    if (row) {
      res.success({
        message: "Done",
      });
    } else {
      res.error(400, (message = "Error create"));
    }
  } catch (error) {
    res.error(404, ((message = "Resource not found"), error));
  }
};
const update = async (req, res) => {
  try {
    const { id } = req.params;
    const { title } = req.body;
    const row = await taskModel.update(id, title);
    if (row) {
      res.success({
        message: "Done",
      });
    } else {
      res.error(400, (message = "Error Update"));
    }
  } catch (error) {
    res.error(404, ((message = "Resource not found"), error));
  }
};
const destroy = async (req, res) => {
  try {
    const { id } = req.params;
    console.log(id);
    const row = await taskModel.destroy(id);
    if (row) {
      res.success({
        message: "Done",
      });
    } else {
      res.error(400, (message = "Error delete"));
    }
  } catch (error) {
    res.error(404, ((message = "Resource not found"), error));
  }
};

module.exports = { findAll, findOne, create, update, destroy };
