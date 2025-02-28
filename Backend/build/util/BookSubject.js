"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.bookSubject = void 0;
const bookObserver_1 = require("./bookObserver");
class BookSubject {
    observers = [];
    attach(observers) {
        this.observers.push(observers);
    }
    detach(observers) {
        this.observers = this.observers.filter((obs) => obs !== observers);
    }
    notifyBookCreated(book) {
        this.observers.forEach((observers) => observers.onBookCreated(book));
    }
    notifyBookUpdated(book) {
        this.observers.forEach((observers) => observers.onBookUpdated(book));
    }
    notifyBookDeteled(bookId) {
        this.observers.forEach((observers) => observers.onBookDelete(bookId));
    }
}
exports.bookSubject = new BookSubject();
exports.bookSubject.attach(bookObserver_1.logObserver);
