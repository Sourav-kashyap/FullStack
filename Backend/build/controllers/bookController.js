"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.deleteBook = exports.updateBook = exports.createBook = exports.getAllBooks = void 0;
const bookModel_1 = require("../models/bookModel");
const authorModel_1 = require("../models/authorModel");
const categoryModel_1 = require("../models/categoryModel");
const BookSubject_1 = require("../util/BookSubject");
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
    try {
        const { title, author, isbn, publishDate, category, price } = req.body;
        if (!title || !author || !isbn || !publishDate || !category || !price) {
            res.status(400).json({ message: "All fields are required" });
            return;
        }
        let isAuthor = await authorModel_1.Author.findOne({ where: { name: author.trim() } });
        if (!isAuthor) {
            isAuthor = await authorModel_1.Author.create({ name: author });
        }
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
        BookSubject_1.bookSubject.notifyBookCreated(book);
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
        // Validate the required fields
        if (!title || !isbn || !price || !author || !category) {
            res.status(400).json({ message: "All fields are required" });
            return;
        }
        const bookId = req.params.id;
        if (!bookId) {
            res.status(400).json({ message: "Invalid Book ID" });
            return;
        }
        // Find the book by primary key
        const book = await bookModel_1.Book.findByPk(bookId);
        if (!book) {
            res.status(404).json({ message: "Book not found" });
            return;
        }
        // Update title, isbn, price, and publishDate
        await book.update({
            title,
            isbn,
            price,
            publishDate,
        });
        // Handle author update
        if (book.dataValues.author !== author) {
            let authorId = book.dataValues.author;
            // Check if the new author exists in the database
            const newAuthor = await authorModel_1.Author.findOne({ where: { name: author } });
            if (newAuthor) {
                // If author exists, update the author ID in the book
                authorId = newAuthor.dataValues.id;
            }
            else {
                // If author does not exist, create a new author and use the new author ID
                const newAuthorCreated = await authorModel_1.Author.create({ name: author });
                authorId = newAuthorCreated.dataValues.id;
            }
            // Update the book with the new author ID
            await book.update({
                author: authorId,
            });
        }
        // Handle category update
        if (book.dataValues.category !== category) {
            // Find the category in the database
            const newCategory = await categoryModel_1.Category.findOne({ where: { name: category } });
            if (!newCategory) {
                res.status(400).json({ message: "Category not found" });
                return;
            }
            // Update the book with the new category ID
            await book.update({
                category: newCategory.dataValues.id,
            });
        }
        BookSubject_1.bookSubject.notifyBookUpdated(book);
        // Respond with success message and the updated book
        res.status(200).json({
            message: "Book updated successfully",
            book,
        });
    }
    catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error while updating the book", error });
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
        BookSubject_1.bookSubject.notifyBookDeteled(Number(bookId));
        res.status(200).json({ message: "Book delete successfully" });
    }
    catch (error) {
        res.status(500).json({ message: "Error while deleting a Book", error });
    }
};
exports.deleteBook = deleteBook;
