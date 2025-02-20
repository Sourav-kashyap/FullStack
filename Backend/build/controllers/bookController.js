"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteBook = exports.updateBook = exports.createBook = exports.getAllBooks = void 0;
const bookModel_1 = require("../models/bookModel");
const authorModel_1 = require("../models/authorModel");
const categoryModel_1 = require("../models/categoryModel");
const getAllBooks = async (req, res) => {
    try {
        const books = await bookModel_1.Book.findAll({
            attributes: ["title", "isbn", "publishDate", "price"],
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
            return res.status(400).json({ message: "All fields are required" });
        }
        let isAuthor = await authorModel_1.Author.findOne({ where: { name: author } });
        if (!isAuthor) {
            isAuthor = await authorModel_1.Author.create({ name: author });
        }
        let isCategory = await categoryModel_1.Category.findOne({ where: { name: category } });
        if (!isCategory) {
            return res.status(400).json({ message: "Category not found" });
        }
        console.log("Author and Category found/created");
        const book = await bookModel_1.Book.create({
            title,
            isbn,
            publishDate,
            price,
            authorId: isAuthor.dataValues.id,
            categoryId: isCategory.dataValues.id,
        });
        console.log("Book created successfully:", book);
        if (!book) {
            return res.status(400).json({
                message: "Book not created",
            });
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
        const { title, isbn, price, authorId, categoryId } = req.body;
        if (!title || !isbn || !price || !authorId || !categoryId) {
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
        const author = await authorModel_1.Author.findOne({ where: { id: authorId } });
        if (!author) {
            res.status(400).json({
                message: "This Author are not valid first create a new Author",
            });
            return;
        }
        const category = categoryModel_1.Category.findOne({ where: { id: categoryId } });
        if (!category) {
            res.status(400).json({
                message: "This Category are not valid first create a new Category",
            });
            return;
        }
        const updatedBook = await book.update({
            title,
            isbn,
            price,
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
