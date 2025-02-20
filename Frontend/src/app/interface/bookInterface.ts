// Book Interface
export interface Book {
  title: string;
  author: string;
  isbn: string; // Changed from number to string for better compatibility
  publishDate: string;
  category: string;
  price: number;
}
