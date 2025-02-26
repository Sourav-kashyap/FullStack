import { DataTypes } from "sequelize";
import { Database } from "../db/db";

const instance = Database.getInstance();

export const Category = instance.sequelize.define(
  "Category",
  {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
      allowNull: false,
    },
    name: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
  },
  {
    freezeTableName: true,
  }
);
