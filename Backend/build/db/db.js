"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Database = void 0;
const sequelize_1 = require("sequelize");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
class Database {
    static instance;
    sequelize;
    constructor() {
        this.sequelize = new sequelize_1.Sequelize(`${process.env.DB_NAME}`, `${process.env.USER_NAME}`, `${process.env.PASSWORD}`, {
            host: `${process.env.HOST}`,
            port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) : undefined,
            dialect: process.env.DIALECT,
        });
    }
    static getInstance() {
        if (!Database.instance) {
            Database.instance = new Database();
        }
        return Database.instance;
    }
    async dbConnect() {
        try {
            await this.sequelize.authenticate();
            console.log("DB Connection has been established successfully.");
        }
        catch (error) {
            console.error("Unable to connect to the database:", error);
        }
    }
}
exports.Database = Database;
