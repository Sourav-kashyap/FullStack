import { Component } from "@angular/core";
import { signInWithPopup } from "firebase/auth";
import { auth, provider } from "../../firebase/firebase";

@Component({
  selector: "app-signin",
  imports: [],
  templateUrl: "./signin.component.html",
  styleUrl: "./signin.component.css",
})
export class SigninComponent {
  async click() {
    console.log("Auth start");

    const loginResponse = await signInWithPopup(auth, provider);
    console.log(loginResponse);
  }
}
