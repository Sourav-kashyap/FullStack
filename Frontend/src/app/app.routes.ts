import { Routes } from "@angular/router";
import { HomeComponent } from "./components/home/home.component";
import { SearchComponent } from "./components/search/search.component";
import { BookFormComponent } from "./components/book-form/book-form.component";
import { DisplayBookComponent } from "./components/display-book/display-book.component";
import { SigninComponent } from "./pages/signin/signin.component";

export const routes: Routes = [
  { path: "", redirectTo: "login", pathMatch: "full" },
  {
    path: "login",
    component: SigninComponent,
  },
  {
    path: "home",
    component: HomeComponent,
  },
  {
    path: "book-form",
    component: BookFormComponent,
  },
  {
    path: "display-books",
    component: DisplayBookComponent,
  },
  {
    path: "search",
    component: SearchComponent,
  },
];
