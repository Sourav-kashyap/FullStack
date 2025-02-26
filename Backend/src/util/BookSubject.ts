import { BookObserver } from "./bookObserver";
import { logObserver } from "./bookObserver";

class BookSubject {
  private observers: BookObserver[] = [];

  attach(observers: BookObserver): void {
    this.observers.push(observers);
  }

  detach(observers: BookObserver): void {
    this.observers = this.observers.filter((obs) => obs !== observers);
  }

  notifyBookCreated(book: any): void {
    this.observers.forEach((observers) => observers.onBookCreated(book));
  }

  notifyBookUpdated(book: any): void {
    this.observers.forEach((observers) => observers.onBookUpdated(book));
  }

  notifyBookDeteled(bookId: number): void {
    this.observers.forEach((observers) => observers.onBookDelete(bookId));
  }
}

export const bookSubject = new BookSubject();
bookSubject.attach(logObserver);
