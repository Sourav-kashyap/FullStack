import { Request, Response } from "express";
import { Book } from "../models/bookModel";
import { Author } from "../models/authorModel";
import { Category } from "../models/categoryModel";

export const getAllBooks = async (req: Request, res: Response) => {
  try {
    const books = await Book.findAll({
      attributes: ["title", "isbn", "publishDate", "price"],
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
  console.log("req.body ->", req.body);
  try {
    const { title, author, isbn, publishDate, category, price } = req.body;

    if (!title || !author || !isbn || !publishDate || !category || !price) {
      return res.status(400).json({ message: "All fields are required" });
    }

    let isAuthor = await Author.findOne({ where: { name: author } });
    if (!isAuthor) {
      isAuthor = await Author.create({ name: author });
    }

    let isCategory = await Category.findOne({ where: { name: category } });
    if (!isCategory) {
      return res.status(400).json({ message: "Category not found" });
    }

    console.log("Author and Category found/created");

    const book = await Book.create({
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
  } catch (error) {
    console.error("Error while creating book:", error);
    res.status(500).json({ message: "Error while creating a Book", error });
  }
};

export const updateBook = async (req: Request, res: Response) => {
  try {
    const { title, isbn, price, authorId, categoryId } = req.body;

    if (!title || !isbn || !price || !authorId || !categoryId) {
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

    const author = await Author.findOne({ where: { id: authorId } });
    if (!author) {
      res.status(400).json({
        message: "This Author are not valid first create a new Author",
      });
      return;
    }

    const category = Category.findOne({ where: { id: categoryId } });
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
