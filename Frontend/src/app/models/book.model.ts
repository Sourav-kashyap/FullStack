// Book Interface
export class Book {
  title: string;
  author: string;
  isbn: string; // Changed from number to string for better compatibility
  publishDate: string;
  category: string;
  price: number;

  constructor(data: Book) {
    this.title = data.title;
    this.author = data.author;
    this.isbn = data.isbn;
    this.publishDate = data.publishDate;
    this.category = data.category;
    this.price = data.price;
  }
}
