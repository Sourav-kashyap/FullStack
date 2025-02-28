import { AnyObject } from "../adapters/anyobject";
import { Observable } from "rxjs";
export declare type HttpObserve = "body" | "events" | "response";
export declare type ResponseType = "arraybuffer" | "blob" | "json" | "text";

export interface ICommand<T> {
  parameters?: AnyObject;
  execute(): Observable<T>;
}
