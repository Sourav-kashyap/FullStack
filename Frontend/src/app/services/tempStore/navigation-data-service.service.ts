import { Injectable } from "@angular/core";

@Injectable({
  providedIn: "root",
})
export class NavigationDataServiceService {
  private data: any;

  constructor() {}

  setData(data: any) {
    this.data = data;
    console.log("dataset successfully");
  }

  getData() {
    return this.data;
  }

  clearData() {
    this.data = null;
  }
}
