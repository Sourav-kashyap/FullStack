import { initializeApp, getApps } from "firebase/app";
import { getAuth, OAuthProvider } from "firebase/auth";

const firebaseConfig = {
  apiKey: process.env["API_KEY"],
  authDomain: process.env["AUTH_DOMAIN"],
  projectId: process.env["PROJECT_ID"],
  storageBucket: process.env["STORAGE_BUCKET"],
  messagingSenderId: process.env["MESSAGING_SENDER_ID"],
  appId: process.env["APP_ID"],
  measurementId: process.env["MEASUREMENT_ID"],
};
const app = !getApps().length ? initializeApp(firebaseConfig) : getApps()[0];
export const auth = getAuth(app);
export const provider = new OAuthProvider("microsoft.com");
