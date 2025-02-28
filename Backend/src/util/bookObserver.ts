export interface BookObserver {
  onBookCreated(book: any): void;
  onBookUpdated(book: any): void;
  onBookDelete(bookId: number): void;
}

export class LogObserver implements BookObserver {
  onBookCreated(book: any): void {
    console.log("Book created:", book.title);
  }

  onBookUpdated(book: any): void {
    console.log("Book Updated:", book.title);
  }

  onBookDelete(bookId: number): void {
    console.log("Book Deleted:", bookId);
  }
}

export const logObserver = new LogObserver();
