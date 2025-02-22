import { filter } from "rxjs/operators";
import { Component, OnInit } from "@angular/core";
import { Router, NavigationEnd } from "@angular/router";
import { BookService } from "../../services/shared/book.service";
import { DatePipe, NgFor, NgIf } from "@angular/common";
import { NavigationDataServiceService } from "../../services/tempStore/navigation-data-service.service";
import { SearchService } from "../../services/search/search.service";
@Component({
  selector: "app-book",
  imports: [NgFor, DatePipe, NgIf],
  templateUrl: "./book.component.html",
  styleUrl: "./book.component.css",
})
export class BookComponent implements OnInit {
  books: any[] = [];
  filteredBooks: any[] = [];
  searchTerm: string = "";

  constructor(
    private router: Router,
    private bookService: BookService,
    private navigationDataService: NavigationDataServiceService,
    private searchService: SearchService
  ) {}

  calculateBookAge(publishDate: string): string {
    const publishedDate = new Date(publishDate);
    const currentDate = new Date();

    let years = currentDate.getFullYear() - publishedDate.getFullYear();
    let months = currentDate.getMonth() - publishedDate.getMonth();
    let days = currentDate.getDate() - publishedDate.getDate();

    if (days < 0) {
      const previousMonth = new Date(
        currentDate.getFullYear(),
        currentDate.getMonth(),
        0
      ).getDate();
      days += previousMonth;
      months--;
    }

    if (months < 0) {
      months += 12;
      years--;
    }
    return `${days} days, ${months} months, ${years} years `;
  }

  fetchBooks() {
    this.bookService.getBooks().subscribe({
      next: (data) => {
        this.books = data;
      },
      error: (error) => {
        console.error("Error fetching books:", error);
      },
      complete: () => {
        console.log("Book fetching completed.");
      },
    });
  }

  ngOnInit() {
    this.fetchBooks();
    this.searchService.searchQuery$.subscribe((query) => {
      this.searchTerm = query;
      this.filterBooks();
    });
  }

  filterBooks() {
    if (!this.searchTerm.trim()) {
      this.filteredBooks = [...this.books];
    } else {
      const searchLower = this.searchTerm.toLowerCase();
      this.filteredBooks = [...this.books].filter(
        (book) =>
          book.title.toLowerCase().includes(searchLower) ||
          book.author.toLowerCase().includes(searchLower) ||
          String(book.isbn).includes(searchLower) || // Convert isbn to string
          book.category.toLowerCase().includes(searchLower)
      );
    }
  }

  editBook(index: number) {
    const bookToEdit = this.books[index];

    this.navigationDataService?.setData({ bookToEdit, index });
    this.router.navigate(["/book-form"]);
  }

  deleteBook(index: number) {
    const bookIDelete = this.books[index];
    this.bookService.deleteBook(bookIDelete.id).subscribe({
      next: (res) => {
        console.log("Book delete ", res);
      },
      error: (err) => {
        console.log("Error", err);
      },
    });
  }

  navigateToBookForm() {
    this.router.navigate(["/book-form"]);
  }
}
