import { AnyObject } from "./anyobject";

export interface IAdapter<T, R = T> {
  adaptToModel(resp: AnyObject): T;
  adaptFromModel(data: Partial<R>): AnyObject;
}
