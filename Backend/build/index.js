"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const dotenv_1 = __importDefault(require("dotenv"));
const cors_1 = __importDefault(require("cors"));
// import { Book } from "./models/bookModel";
// import { Author } from "./models/authorModel";
// import { Category } from "./models/categoryModel";
const db_1 = require("./db/db");
require("./association/association");
const bookRoute_1 = __importDefault(require("./routes/bookRoute"));
const authorRoute_1 = __importDefault(require("./routes/authorRoute"));
const categoryRoute_1 = __importDefault(require("./routes/categoryRoute"));
dotenv_1.default.config();
const app = (0, express_1.default)();
const PORT = Number(process.env.PORT) || 8088;
app.use(express_1.default.json());
app.use((0, cors_1.default)());
app.use("/api/v1/book", bookRoute_1.default);
app.use("/api/v1/author", authorRoute_1.default);
app.use("/api/v1/category", categoryRoute_1.default);
app.get("/", (req, res) => {
    res.send("Home:");
});
// Book.sync();
// Author.sync();
// Category.sync();
app.listen(PORT, async () => {
    try {
        console.log(`Server running on port is ${PORT}`);
        const instance = db_1.Database.getInstance();
        instance.dbConnect();
    }
    catch (error) {
        console.error("Error starting server:", error);
    }
});
