const express = require("express");
const tasksController = require("@/controllers/task.controller");
const router = express.Router();

router.get("/", tasksController.findAll);
router.get("/:id", tasksController.findOne);
router.post("/", tasksController.create);
router.put("/:id", tasksController.update);
router.delete("/:id", tasksController.destroy);
module.exports = router;
