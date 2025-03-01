import { NUMBER, Sequelize } from "sequelize";
import dotenv from "dotenv";
dotenv.config();

export class Database {
  private static instance: Database;
  public sequelize: Sequelize;
  private constructor() {
    this.sequelize = new Sequelize(
      `${process.env.DB_NAME}`,
      `${process.env.USER_NAME}`,
      `${process.env.PASSWORD}`,
      {
        host: `${process.env.HOST}`,
        port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : undefined,
        dialect: process.env.DIALECT as "mysql",
      }
    );
  }

  public static getInstance(): Database {
    if (!Database.instance) {
      Database.instance = new Database();
    }
    return Database.instance;
  }

  public async dbConnect() {
    try {
      await this.sequelize.authenticate();
      console.log("DB Connection has been established successfully.");
    } catch (error) {
      console.error("Unable to connect to the database:", error);
    }
  }
}
