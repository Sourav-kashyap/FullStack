import { HttpClient } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { Observable, throwError } from "rxjs";
import { tap, catchError } from "rxjs/operators";
import { Book } from "../../interface/bookInterface";

@Injectable({
  providedIn: "root",
})
export class BookService {
  private apiUrl = "http://localhost:8000/api/v1/books";

  constructor(private http: HttpClient) {}

  getBooks(): Observable<Book[]> {
    return this.http.get<Book[]>(`${this.apiUrl}/allBooks`);
  }

  addBook(bookData: Book): Observable<Book> {
    return this.http.post<Book>(`${this.apiUrl}/addBook`, bookData).pipe(
      tap((response) => console.log("Book added successfully:", response)),
      catchError((error) => {
        console.error("Error adding book:", error);
        return throwError(() => error);
      })
    );
  }

  updateBook(index: number, updatedBook: Book): Observable<Book> {
    return this.http
      .patch<Book>(`${this.apiUrl}/updateBook/${index}`, updatedBook)
      .pipe(
        tap((response) => console.log("Book updated successfully:", response)),
        catchError((error) => {
          console.error("Error updating book:", error);
          return throwError(() => error);
        })
      );
  }

  deleteBook(index: number): Observable<void> {
    return this.http.delete<void>(`${this.apiUrl}/deleteBook/${index}`).pipe(
      tap(() => console.log("Book deleted successfully:")),
      catchError((error) => {
        console.error("Error while deleting book:", error);
        return throwError(() => error);
      })
    );
  }
}
