import { HttpClient } from "@angular/common/http";
import { Injectable } from "@angular/core";
import { Observable, throwError } from "rxjs";
import { tap, catchError } from "rxjs/operators";
import { Book } from "../../interface/bookInterface";

@Injectable({
  providedIn: "root",
})
export class BookService {
  private apiUrl = "http://localhost:8088/api/v1/book";

  constructor(private http: HttpClient) {}

  getBooks(): Observable<Book[]> {
    return this.http.get<Book[]>(`${this.apiUrl}/getAllBooks`);
  }

  addBook(bookData: Book): Observable<Book> {
    return this.http.post<Book>(`${this.apiUrl}/createBook`, bookData).pipe(
      tap((response) => console.log("Book added successfully:", response)),
      catchError((error) => {
        console.error("Error adding book:", error);
        // You can also log the full error response body here
        console.error("Error response:", error?.error); // Inspect error body
        return throwError(() => error);
      })
    );
  }

  updateBook(index: number, updatedBook: Book, id: number): Observable<Book> {
    return this.http
      .patch<Book>(`${this.apiUrl}/updateBook/${id}`, updatedBook)
      .pipe(
        tap((response) => console.log("Book updated successfully:", response)),
        catchError((error) => {
          console.error("Error updating book:", error);
          return throwError(() => error);
        })
      );
  }

  deleteBook(id: number): Observable<void> {
    console.log("id recieved in the api ->", id);

    return this.http.delete<void>(`${this.apiUrl}/deleteBook/${id}`).pipe(
      tap(() => console.log("Book deleted successfully:")),
      catchError((error) => {
        console.error("Error while deleting book:", error);
        return throwError(() => error);
      })
    );
  }
}
