import express from "express";
import {
  getAllBooks,
  createBook,
  updateBook,
  deleteBook,
  // getBookById,
} from "../controllers/bookController";
import { ensureAuthenticated } from "../util/authMiddleware";
const router = express.Router();

router.get("/getAllBooks", ensureAuthenticated, getAllBooks);
router.post("/createBook", ensureAuthenticated, createBook);
// router.get("/getBook/:id", getBookById);
router.patch("/updateBook/:id", ensureAuthenticated, updateBook);
router.delete("/deleteBook/:id", ensureAuthenticated, deleteBook);

export default router;
