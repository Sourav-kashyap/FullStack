"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.logObserver = exports.LogObserver = void 0;
class LogObserver {
    onBookCreated(book) {
        console.log("Book created:", book.title);
    }
    onBookUpdated(book) {
        console.log("Book Updated:", book.title);
    }
    onBookDelete(bookId) {
        console.log("Book Deleted:", bookId);
    }
}
exports.LogObserver = LogObserver;
exports.logObserver = new LogObserver();
