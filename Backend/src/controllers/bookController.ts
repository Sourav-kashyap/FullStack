import { Request, Response } from "express";
import { Book } from "../models/bookModel";
import { Author } from "../models/authorModel";
import { Category } from "../models/categoryModel";
import { where } from "sequelize";

export const getAllBooks = async (req: Request, res: Response) => {
  try {
    const books = await Book.findAll({
      attributes: ["id", "title", "isbn", "publishDate", "price"],
      include: [
        {
          model: Author,
          attributes: ["name"],
        },
        {
          model: Category,
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
  } catch (error) {
    res.status(500).json({ message: "Error while fetching all Books", error });
  }
};

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

export const createBook = async (req: Request, res: Response) => {
  try {
    const { title, author, isbn, publishDate, category, price } = req.body;

    if (!title || !author || !isbn || !publishDate || !category || !price) {
      res.status(400).json({ message: "All fields are required" });
      return;
    }

    let isAuthor = await Author.findOne({ where: { name: author } });
    if (!isAuthor) {
      isAuthor = await Author.create({ name: author });
    }


    let isCategory = await Category.findOne({ where: { name: category } });
    if (!isCategory) {
      res.status(400).json({ message: "Category not found" });
      return;
    }

    const book = await Book.create({
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
  } catch (error) {
    console.error("Error while creating book:", error);
    res.status(500).json({ message: "Error while creating a Book", error });
  }
};

export const updateBook = async (req: Request, res: Response) => {
  try {
    const { title, isbn, price, publishDate, author, category } = req.body;

    if (!title || !isbn || !price || !author || !category) {
      res.status(400).json({ message: "All fields are required" });
    }

    const bookId = req.params.id;

    if (!bookId) {
      res.status(400).json({ message: "invalid Book id" });
    }

    const book = await Book.findByPk(bookId);

    if (!book) {
      res.status(400).json({ mesasge: "Book not found" });
      return;
    }

    const authorId = await book.dataValues.author;

    const newAuthorName = await Author.update(
      { name: author },
      { where: { id: authorId } }
    );

    const categoryId = await book.dataValues.category;

    const newCategoryName = await Category.update(
      { name: category },
      { where: { id: categoryId } }
    );

    const updatedBook = await book.update({
      title,
      isbn,
      price,
      publishDate,
      authorId,
      categoryId,
    });

    if (!updateBook) {
      res.status(400).json({
        message: "Book not updated",
      });
      return;
    }

    res.status(201).json({ message: "Book Updated successfully", updateBook });
  } catch (error) {
    res.status(500).json({ message: "Error while updating a Book", error });
  }
};

export const deleteBook = async (req: Request, res: Response) => {
  try {
    const bookId = req.params.id;

    if (!bookId) {
      res.status(400).json({ message: "invalid Book id" });
    }

    const book = await Book.findByPk(bookId);

    if (!book) {
      res.status(400).json({
        message: "Book not found",
      });
      return;
    }
    await book.destroy();

    res.status(200).json({ message: "Book delete successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error while deleting a Book", error });
  }
};
