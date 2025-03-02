"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.initPassport = void 0;
const passport_1 = __importDefault(require("passport"));
const passport_azure_ad_1 = require("passport-azure-ad");
const dotenv_1 = __importDefault(require("dotenv"));
dotenv_1.default.config();
const initPassport = async () => {
    // Get environment variables and ensure they are defined
    const idmetadata = `${process.env.CLOUD_INSTANCE}${process.env.AZURE_TENANT_ID}/.well-known/openid-configuration`;
    const clientId = process.env.AZURE_CLIENT_ID;
    const clientSecret = process.env.AZURE_CLIENT_SECRET;
    const responseType = process.env.RESPONSE_TYPE;
    const responseMode = process.env.RESPONSE_MODE;
    const redirectUrl = process.env.REDIRECT_URI;
    // Throw error if required environment variables are missing
    if (!clientId ||
        !clientSecret ||
        !responseType ||
        !responseMode ||
        !redirectUrl) {
        throw new Error("Missing required environment variables.");
    }
    // Define the configuration object
    const azureADConfig = {
        identityMetadata: idmetadata,
        clientID: clientId,
        clientSecret: clientSecret,
        responseType: responseType,
        responseMode: responseMode,
        redirectUrl: redirectUrl,
        allowHttpForRedirectUrl: true, // Set to true for local development
        isB2C: false, // Set to true if using Azure AD B2C
        validateIssuer: false, // Set to true if you want to validate the issuer
        passReqToCallback: true, // `true` as a literal value
        useCookieInsteadOfSession: false, // Use cookies for session management
        scope: ["openid", "profile", "email"], // Specify the required scopes
        loggingLevel: "info", // Adjust logging level as needed
    };
    // Callback function
    const callbackFunction = (req, iss, sub, profile, accessToken, refreshToken, done) => {
        if (accessToken) {
            console.log("Received accessToken - " + accessToken);
        }
        if (refreshToken) {
            console.log("Received refreshToken - " + refreshToken);
        }
        if (!profile.oid) {
            console.log("Received accessToken - " + accessToken);
            return done(new Error("No oid found"), null);
        }
        if (profile) {
            console.log("profile - " + JSON.stringify(profile));
        }
        return done(null, profile);
    };
    //   Initialize the OIDC strategy
    passport_1.default.use(new passport_azure_ad_1.OIDCStrategy(azureADConfig, callbackFunction));
};
exports.initPassport = initPassport;
