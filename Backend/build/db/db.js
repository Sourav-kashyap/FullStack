"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Database = void 0;
const sequelize_1 = require("sequelize");
class Database {
    static instance;
    sequelize;
    constructor() {
        this.sequelize = new sequelize_1.Sequelize("bms", "sourav", "sourav", {
            host: "localhost",
            port: 3306,
            dialect: "mysql",
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
