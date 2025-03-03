import { NextFunction } from "express";
export const ensureAuthenticated = (req: any, res: any, next: NextFunction) => {
  if (req.session.isAuthenticated) {
    return next();
  }
  res.redirect("http://localhost:4200/login");
};
