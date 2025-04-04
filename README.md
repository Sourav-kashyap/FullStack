# Fullstack Book Management System (Angular, Node.js, MySQL)

## 📖 Project Description

The **Book Management System** is a full-stack application designed to facilitate the management of books in a library or personal collection. This project integrates with the **Google Books API** to fetch book data based on search queries, such as genres, authors, or titles. Users can add, view, search, and organize book-related data efficiently.

- **Frontend**: Angular with TypeScript
- **Backend**: Node.js with Express and TypeScript
- **Database**: MySQL for storing user data and books

## 🚀 Features

- **Search for Books**: Use the Google Books API to search for books by title, genre, author, or ISBN.
- **View Book Details**: View detailed information about each book, including its title, author, publisher, and more.
- **Organize Books**: Filter and sort the results to better manage the book data.
- **Database Integration**: Store user data and book data in a MySQL database for persistence.

---

## 🛠️ Technologies Used

- **Frontend**:

  - **Angular** (for creating dynamic web pages)
  - **TypeScript** (for type safety and better development experience)

- **Backend**:

  - **Node.js** (JavaScript runtime for the server)
  - **Express** (web framework for building APIs)
  - **TypeScript** (for better code maintainability and type checking)

- **Database**:

  - **MySQL** (for storing and managing book and user data)

---

## 📥 Installation & Setup

### Prerequisites

Before setting up the project, make sure you have the following installed:

- **Node.js** (Make sure Node.js is installed on your system)
- **npm** (Node Package Manager comes with Node.js)
- **MySQL** (Database for storing data)
- **Angular CLI** (Install Angular CLI globally if not already installed)

To install Angular CLI:

```bash
npm install -g @angular/cli
```

## 🗂️ Project Structure

This repository consists of two main folders:

### Frontend: Contains the Angular project (client-side).

### Backend: Contains the Node.js, Express, and MySQL (server-side).

# How to Clone the Repository

### Follow these steps to clone this repository to your local system:

## Prerequisites:

- Ensure Git is installed on your computer.

- Download Git if you don’t already have it.

- Have a terminal or command-line tool available (e.g., Command Prompt, Terminal, or Git Bash).

# Steps to Clone the Repository

- Open the terminal or command-line tool.

- Navigate to the directory where you want to clone the repository:

- cd /path/to/your/directory

## Copy the repository URL:

- https://github.com/Sourav-kashyap/FullStack.git
- Run the git clone command followed by the URL:

- git clone https://github.com/Sourav-kashyap/FullStack.git

- After the cloning process is complete, navigate into the cloned repository directory:

- cd Book-Management-System
- You should see two folders: Frontend and Backend.

# 📂 Frontend Setup (Angular)

### Navigate to the Frontend directory:

- cd Frontend
- Install the necessary dependencies:
- npm install

### Run the Angular application:

- ng serve
- Open your browser and navigate to http://localhost:4200 to access the Book Management System Fullstack.

# ⚙️ Backend Setup (Node.js + Express)

- Navigate to the Backend directory:
- cd Backend
- Install the necessary dependencies:
- npm install
- Configure MySQL:

- Create a MySQL database and configure the connection details in the config file located in the Backend folder.

- Run SQL queries to create the necessary tables for storing book and user data.

- Run the backend server:

npm start

- The backend should now be running on http://localhost:3000.

# 🔒 How to Close/Stop the Project

- To stop the running applications, go back to your terminal and press Ctrl + C in both the frontend and backend directories. This will terminate the servers and stop the application.

# 📁 Folder Structure

- The folder structure of this project looks like this:

Book-Management-System/
│
├── Frontend/
│ ├── src/
│ │ ├── app/
│ │ ├── assets/
│ │ └── ... (other Angular files)
│ ├── package.json
│ ├── angular.json
│ └── README.md
│
├── Backend/
│ ├── src/
│ │ ├── controllers/
│ │ ├── models/
│ │ ├── routes/
│ │ ├── server.ts
│ │ └── ... (other Express files)
│ ├── package.json
│ ├── tsconfig.json
│ └── README.md
│
└── README.md

## 🚨 Troubleshooting

- Frontend Not Starting: Make sure you've installed the Angular dependencies and have run ng serve from the Frontend folder.

## Backend Not Connecting to Database:

- Ensure your MySQL database is running and that the correct configuration is set in the Backend/config file.

## CORS Issues:

- Make sure to configure CORS in your Express server if you're facing issues connecting the frontend and backend locally.

## 🎉 Congratulations! You've successfully set up the Fullstack Book Management System.
