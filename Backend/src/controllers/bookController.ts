import { Request, Response } from "express";
import { Book } from "../models/bookModel";
import { Author } from "../models/authorModel";
import { Category } from "../models/categoryModel";
import { bookSubject } from "../util/BookSubject";

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

    let isAuthor = await Author.findOne({ where: { name: author.trim() } });
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

    bookSubject.notifyBookCreated(book);

    res.status(201).json({ message: "Book created successfully", book });
  } catch (error) {
    console.error("Error while creating book:", error);
    res.status(500).json({ message: "Error while creating a Book", error });
  }
};

export const updateBook = async (req: Request, res: Response) => {
  try {
    const { title, isbn, price, publishDate, author, category } = req.body;

    // Validate the required fields
    if (!title || !isbn || !price || !author || !category) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const bookId = req.params.id;

    if (!bookId) {
      return res.status(400).json({ message: "Invalid Book ID" });
    }

    // Find the book by primary key
    const book = await Book.findByPk(bookId);

    if (!book) {
      return res.status(404).json({ message: "Book not found" });
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
      const newAuthor = await Author.findOne({ where: { name: author } });

      if (newAuthor) {
        // If author exists, update the author ID in the book
        authorId = newAuthor.dataValues.id;
      } else {
        // If author does not exist, create a new author and use the new author ID
        const newAuthorCreated = await Author.create({ name: author });
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
      const newCategory = await Category.findOne({ where: { name: category } });

      if (!newCategory) {
        return res.status(400).json({ message: "Category not found" });
      }

      // Update the book with the new category ID
      await book.update({
        category: newCategory.dataValues.id,
      });
    }
    bookSubject.notifyBookUpdated(book);
    // Respond with success message and the updated book
    res.status(200).json({
      message: "Book updated successfully",
      book,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error while updating the book", error });
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
    bookSubject.notifyBookDeteled(Number(bookId));
    res.status(200).json({ message: "Book delete successfully" });
  } catch (error) {
    res.status(500).json({ message: "Error while deleting a Book", error });
  }
};
