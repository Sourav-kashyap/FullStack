import { Injectable } from "@angular/core";
import { IAdapter } from "./i-adapters";
import { Book } from "../models/book.model";

@Injectable({
  providedIn: "root",
})
export class BookAdapter implements IAdapter<Book[]> {
  adaptToModel(resp: Book[]) {
    console.log("res->", resp);
    return resp.map((book) => new Book(book));
  }

  adaptFromModel(data: any): any {
    return data;
  }
}
