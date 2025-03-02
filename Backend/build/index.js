"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const dotenv_1 = __importDefault(require("dotenv"));
const cors_1 = __importDefault(require("cors"));
const passport_1 = __importDefault(require("passport"));
const authRoute_1 = __importDefault(require("./routes/authRoute"));
const express_session_1 = __importDefault(require("express-session"));
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
// Use express-session middleware before initializing Passport
app.use((0, express_session_1.default)({
    secret: process.env.SESSION_SECRET || "default-secret", // Replace with a secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to `true` if using HTTPS
}));
app.use(express_1.default.json());
app.use((0, cors_1.default)());
app.use("/api/v1/book", bookRoute_1.default);
app.use("/api/v1/author", authorRoute_1.default);
app.use("/api/v1/category", categoryRoute_1.default);
app.use(passport_1.default.initialize());
app.use(passport_1.default.session());
app.use(authRoute_1.default);
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
