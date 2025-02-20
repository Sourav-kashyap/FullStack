import { Component, OnInit } from "@angular/core";
import {
  ReactiveFormsModule,
  FormGroup,
  FormControl,
  Validators,
} from "@angular/forms";
import { Router } from "@angular/router";
import { NgFor } from "@angular/common";
import { BookService } from "../../services/shared/book.service";
import { NavigationDataServiceService } from "../../services/tempStore/navigation-data-service.service";

@Component({
  selector: "app-form",
  imports: [ReactiveFormsModule, NgFor],
  templateUrl: "./form.component.html",
  styleUrl: "./form.component.css",
})
export class FormComponent implements OnInit {
  editIndex: number | null = null;

  constructor(
    private router: Router,
    private bookService: BookService,
    private navigationDataService: NavigationDataServiceService
  ) {}

  categories = [
    "Fiction",
    "Non-fiction",
    "Fantasy",
    "Science",
    "Biography",
    "History",
    "Horror",
    "Children",
    "Language Arts & Disciplines",
    "Literary Criticism",
    "Uncategorized",
    "Performing Arts",
    "Other",
  ];

  bookDetails: FormGroup = new FormGroup({
    title: new FormControl("", [Validators.required]),
    author: new FormControl("", [Validators.required]),
    isbn: new FormControl("", [Validators.required, Validators.minLength(4)]),
    publishDate: new FormControl("", [Validators.required]),
    category: new FormControl("", [Validators.required]),
    price: new FormControl("", [Validators.required, Validators.min(1)]),
  });

  ngOnInit() {
    const state = this.navigationDataService.getData();
    if (state) {
      this.editIndex = state.index;
      this.bookDetails.patchValue(state.bookToEdit);
      this.navigationDataService.clearData();
    }
  }

  onSubmit() {
    const bookData = this.bookDetails.value;
    if (this.editIndex !== null) {
      this.bookService.updateBook(this.editIndex, bookData);
    } else {
      this.bookService.addBook(bookData).subscribe({
        next: (response) => console.log("API Response:", response),
        error: (err) => console.error("API Error:", err),
      });
    }
    this.router.navigate(["/display-books"]);
  }
}
