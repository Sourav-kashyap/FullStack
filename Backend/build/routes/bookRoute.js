"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const bookController_1 = require("../controllers/bookController");
const authMiddleware_1 = require("../util/authMiddleware");
const router = express_1.default.Router();
router.get("/getAllBooks", authMiddleware_1.ensureAuthenticated, bookController_1.getAllBooks);
router.post("/createBook", authMiddleware_1.ensureAuthenticated, bookController_1.createBook);
// router.get("/getBook/:id", getBookById);
router.patch("/updateBook/:id", authMiddleware_1.ensureAuthenticated, bookController_1.updateBook);
router.delete("/deleteBook/:id", authMiddleware_1.ensureAuthenticated, bookController_1.deleteBook);
exports.default = router;
