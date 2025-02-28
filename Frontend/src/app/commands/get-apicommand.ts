import { HttpHeaders, HttpParams } from "@angular/common/http";
import { Observable } from "rxjs";
import { map } from "rxjs/operators";
import { IAdapter } from "../adapters/i-adapters";
import { ApiService } from "../services/api.service";
import { ICommand, HttpObserve, ResponseType } from "./i-command";
import { AnyObject } from "../adapters/anyobject";

export abstract class GetAPICommand<T, R = T> implements ICommand<T> {
  constructor(
    protected readonly apiService: ApiService,
    protected readonly adapter: IAdapter<T, R>,
    protected readonly uri: string
  ) {}

  parameters?: {
    query?: HttpParams;
    headers?: HttpHeaders;
    observe?: HttpObserve;
    responseType?: ResponseType;
  };

  execute(): Observable<T> {
    let options: AnyObject;
    if (this.parameters) {
      options = {
        observe: this.parameters.observe || "body",
      };

      if (this.parameters.headers) {
        options["headers"] = this.parameters.headers;
      }

      if (this.parameters.query) {
        options["params"] = this.parameters.query;
      }

      if (this.parameters.responseType) {
        options["responseType"] = this.parameters.responseType;
      }
    }

    return this.apiService
      .get(this.uri)
      .pipe(map((resp) => this.adapter.adaptToModel(resp)));
  }
}
