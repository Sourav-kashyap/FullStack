import { DataTypes } from "sequelize";
import { Database } from "../db/db";

const instance = Database.getInstance();

export const Book = instance.sequelize.define(
  "Book",
  {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      allowNull: false,
    },
    title: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    isbn: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    publishDate: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    price: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    author: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "Author",
        key: "id",
      },
    },
    category: {
      type: DataTypes.INTEGER,
      allowNull: false,
      references: {
        model: "Category",
        key: "id",
      },
    },
  },
  {
    freezeTableName: true,
  }
);
