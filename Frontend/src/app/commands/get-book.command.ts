import { IAdapter } from "../adapters/i-adapters";
import { ApiService } from "../services/api.service";
import { GetAPICommand } from "./get-apicommand";

export class GetBooksCommand<T> extends GetAPICommand<T> {
  constructor(apiService: ApiService, adapter: IAdapter<T>) {
    super(apiService, adapter, `http://localhost:8088/api/v1/book/getAllBooks`);
  }
}
