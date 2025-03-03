"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ensureAuthenticated = void 0;
const ensureAuthenticated = (req, res, next) => {
    if (req.session.isAuthenticated) {
        return next();
    }
    res.redirect("http://localhost:4200/login");
};
exports.ensureAuthenticated = ensureAuthenticated;
