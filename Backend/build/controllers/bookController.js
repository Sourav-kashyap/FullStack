"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteBook = exports.updateBook = exports.createBook = exports.getAllBooks = void 0;
const bookModel_1 = require("../models/bookModel");
const authorModel_1 = require("../models/authorModel");
const categoryModel_1 = require("../models/categoryModel");
const getAllBooks = async (req, res) => {
    try {
        const books = await bookModel_1.Book.findAll({
            attributes: ["id", "title", "isbn", "publishDate", "price"],
            include: [
                {
                    model: authorModel_1.Author,
                    attributes: ["name"],
                },
                {
                    model: categoryModel_1.Category,
                    attributes: ["name"],
                },
            ],
        });
        if (!books) {
            res.status(400).json({
                message: "Books not found in the DB",
            });
            return;
        }
        res.status(200).json(books);
    }
    catch (error) {
        res.status(500).json({ message: "Error while fetching all Books", error });
    }
};
exports.getAllBooks = getAllBooks;
// export const getBookById = async (req: Request, res: Response) => {
//   try {
//     const bookId = req.params.id;
//     if (!bookId) {
//       res.status(400).json({ message: "invalid Book id" });
//     }
//     const book = await Book.findByPk(bookId);
//     if (!book) {
//       res.status(400).json({
//         message: "Book not found",
//       });
//       return;
//     }
//     res.status(200).json(book);
//   } catch (error) {
//     res.status(500).json({ message: "Error fetching Book", error });
//   }
// };
const createBook = async (req, res) => {
    console.log("req.body ->", req.body);
    try {
        const { title, author, isbn, publishDate, category, price } = req.body;
        if (!title || !author || !isbn || !publishDate || !category || !price) {
            res.status(400).json({ message: "All fields are required" });
            return;
        }
        let isAuthor = await authorModel_1.Author.findOne({ where: { name: author } });
        if (!isAuthor) {
            isAuthor = await authorModel_1.Author.create({ name: author });
        }
        console.log("isAuthor ->", isAuthor);
        let isCategory = await categoryModel_1.Category.findOne({ where: { name: category } });
        if (!isCategory) {
            res.status(400).json({ message: "Category not found" });
            return;
        }
        const book = await bookModel_1.Book.create({
            title,
            isbn,
            publishDate,
            price,
            author: isAuthor.dataValues.id,
            category: isCategory.dataValues.id,
        });
        if (!book) {
            res.status(400).json({
                message: "Book not created",
            });
            return;
        }
        res.status(201).json({ message: "Book created successfully", book });
    }
    catch (error) {
        console.error("Error while creating book:", error);
        res.status(500).json({ message: "Error while creating a Book", error });
    }
};
exports.createBook = createBook;
const updateBook = async (req, res) => {
    try {
        const { title, isbn, price, publishDate, author, category } = req.body;
        if (!title || !isbn || !price || !author || !category) {
            res.status(400).json({ message: "All fields are required" });
        }
        const bookId = req.params.id;
        if (!bookId) {
            res.status(400).json({ message: "invalid Book id" });
        }
        const book = await bookModel_1.Book.findByPk(bookId);
        if (!book) {
            res.status(400).json({ mesasge: "Book not found" });
            return;
        }
        const authorId = await book.dataValues.author;
        const newAuthorName = await authorModel_1.Author.update({ name: author }, { where: { id: authorId } });
        const categoryId = await book.dataValues.category;
        const newCategoryName = await categoryModel_1.Category.update({ name: category }, { where: { id: categoryId } });
        const updatedBook = await book.update({
            title,
            isbn,
            price,
            publishDate,
            authorId,
            categoryId,
        });
        if (!exports.updateBook) {
            res.status(400).json({
                message: "Book not updated",
            });
            return;
        }
        res.status(201).json({ message: "Book Updated successfully", updateBook: exports.updateBook });
    }
    catch (error) {
        res.status(500).json({ message: "Error while updating a Book", error });
    }
};
exports.updateBook = updateBook;
const deleteBook = async (req, res) => {
    try {
        const bookId = req.params.id;
        if (!bookId) {
            res.status(400).json({ message: "invalid Book id" });
        }
        const book = await bookModel_1.Book.findByPk(bookId);
        if (!book) {
            res.status(400).json({
                message: "Book not found",
            });
            return;
        }
        await book.destroy();
        res.status(200).json({ message: "Book delete successfully" });
    }
    catch (error) {
        res.status(500).json({ message: "Error while deleting a Book", error });
    }
};
exports.deleteBook = deleteBook;
