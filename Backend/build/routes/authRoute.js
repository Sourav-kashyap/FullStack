"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const passport_1 = __importDefault(require("passport"));
const passport_config_1 = require("../util/passport-config");
(0, passport_config_1.initPassport)();
const router = express_1.default.Router();
passport_1.default.serializeUser((user, done) => {
    done(null, user);
});
passport_1.default.deserializeUser((obj, done) => {
    done(null, obj);
});
router.get("/login", passport_1.default.authenticate("azuread-openidconnect"));
router.get("/logout", function (req, res, next) {
    req.logout((err) => {
        if (err) {
            return next(err);
        }
        req.session.destroy(() => {
            res.redirect(process.env.LOGOUT_URL);
        });
    });
});
router.post("/auth/callback", passport_1.default.authenticate("azuread-openidconnect", {
    failureRedirect: "/auth-failure",
}), regenerateSessionAfterAuthentication, function (req, res) {
    res.redirect(`${process.env.APPLICATION_URL}`);
});
router.get("/auth-success", (req, res) => {
    const token = req?.user?._json?.email;
    const name = req?.user?._json?.given_name;
    res.redirect(`${process.env.APPLICATION_URL}`);
});
router.get("/auth-failure", (req, res) => {
    res.status(401).json({ message: "Authentication failed" });
});
router.get("/getLoggedInUser", (req, res) => {
    if (req.session.passport) {
        res.json({
            username: req.session.passport.user?.displayName,
            email: req.session.passport.user?._json?.email,
        });
    }
    else {
        res.json({ username: null, email: null });
    }
});
function regenerateSessionAfterAuthentication(req, res, next) {
    var passportInstance = req.session.passport;
    return req.session.regenerate((err) => {
        if (err) {
            return next(err);
        }
        req.session.passport = passportInstance;
        req.session.isAuthenticated = true;
        return req.session.save(next);
    });
}
exports.default = router;
