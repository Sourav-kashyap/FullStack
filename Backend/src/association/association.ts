import { Book } from "../models/bookModel";
import { Author } from "../models/authorModel";
import { Category } from "../models/categoryModel";

Author.hasMany(Book, {
  foreignKey: "author",
  onDelete: "CASCADE",
});

Book.belongsTo(Author, {
  foreignKey: "author",
});

Category.hasMany(Book, {
  foreignKey: "category",
  onDelete: "CASCADE",
});

Book.belongsTo(Category, {
  foreignKey: "category",
});
