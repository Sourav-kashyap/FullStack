import express, { Application, Request, Response, NextFunction } from "express";
import dotenv from "dotenv";
import cors from "cors";
import passport from "passport";
import AuthRoutes from "./routes/authRoute";
import session from "express-session";

// import { Book } from "./models/bookModel";
// import { Author } from "./models/authorModel";
// import { Category } from "./models/categoryModel";

import { Database } from "./db/db";
import "./association/association";
import bookRouter from "./routes/bookRoute";
import authorRouter from "./routes/authorRoute";
import categoryRouter from "./routes/categoryRoute";

dotenv.config();

const app: Application = express();
const PORT: number = Number(process.env.PORT) || 8088;

// Use express-session middleware before initializing Passport
app.use(
  session({
    secret: process.env.SESSION_SECRET || "default-secret", // Replace with a secret key
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }, // Set to `true` if using HTTPS
  })
);

app.use(express.json());
app.use(cors());
app.use("/api/v1/book", bookRouter);
app.use("/api/v1/author", authorRouter);
app.use("/api/v1/category", categoryRouter);
app.use(passport.initialize());
app.use(passport.session());
app.use(AuthRoutes);

app.get("/", (req: Request, res: Response) => {
  res.send("Home:");
});

// Book.sync();
// Author.sync();
// Category.sync();

app.listen(PORT, async () => {
  try {
    console.log(`Server running on port is ${PORT}`);
    const instance = Database.getInstance();
    instance.dbConnect();
  } catch (error) {
    console.error("Error starting server:", error);
  }
});
