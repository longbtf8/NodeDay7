const express = require("express");
const router = express.Router();
const userController = require("@/controllers/user.controller");
const authRequired = require("@/middlewares/authRequired");
router.get("/", userController.findAll);
router.get("/search", authRequired, userController.findEmail);
module.exports = router;
