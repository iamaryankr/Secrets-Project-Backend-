import express from "express";
import bodyParser from "body-parser";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";
import pkg from "pg";
const { Pool } = pkg;
import path from "path";
import { fileURLToPath } from "url";
import cors from "cors";

// Determine __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Initialize environment variables
env.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// Configure session management with a cookie configuration.
// Use secure cookies only in production.
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000, // 1 day in milliseconds
      secure: process.env.NODE_ENV === "production", // true in production, false locally
      httpOnly: true,
    },
  })
);

// Enable CORS for your frontend URL with credentials allowed
// app.use(
//   cors({
//     origin: "https://secrets-project-backend.vercel.app", // Replace with your frontend URL
//     methods: ["GET", "POST", "PUT", "DELETE"],
//     credentials: true,
//   })
// );

// Parse form data
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the public directory
app.use(express.static(path.join(__dirname, "public")));

// Set up EJS as the templating engine and point to views folder
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Initialize Passport and let it use sessions
app.use(passport.initialize());
app.use(passport.session());

// Create a new PostgreSQL pool using environment variables
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  ssl:
    process.env.DB_SSL === "true"
      ? { rejectUnauthorized: false }
      : false,
});

// ROUTES

// Home route
app.get("/", (req, res) => {
  res.render("home.ejs");
});

// Login page
app.get("/login", (req, res) => {
  res.render("login.ejs");
});

// Registration page
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// Logout route
app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

// Secrets page (protected)
app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const result = await pool.query(
        "SELECT secret FROM users WHERE email = $1",
        [req.user.email]
      );
      const secret = result.rows[0]?.secret;
      res.render("secrets.ejs", {
        secret: secret || "Jack Bauer is my hero.",
      });
    } catch (err) {
      console.error("Error fetching secret:", err);
      res.redirect("/login");
    }
  } else {
    res.redirect("/login");
  }
});

// Submit page (protected)
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

// Google authentication routes
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Login POST route using local strategy
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

// Registration POST route
app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await pool.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );
    if (checkResult.rows.length > 0) {
      // Email already exists, redirect to login
      return res.redirect("/login");
    } else {
      // Hash the password using async/await
      const hash = await bcrypt.hash(password, saltRounds);
      const result = await pool.query(
        "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
        [email, hash]
      );
      const user = result.rows[0];
      // Log the user in after registration
      req.login(user, (err) => {
        if (err) {
          console.error("Login error after registration:", err);
          return res.redirect("/login");
        }
        res.redirect("/secrets");
      });
    }
  } catch (err) {
    console.error("Error during registration:", err);
    res.redirect("/register");
  }
});

// Submit POST route to update secret (protected)
app.post("/submit", async (req, res) => {
  const submittedSecret = req.body.secret;
  try {
    await pool.query("UPDATE users SET secret = $1 WHERE email = $2", [
      submittedSecret,
      req.user.email,
    ]);
    res.redirect("/secrets");
  } catch (err) {
    console.error("Error updating secret:", err);
    res.redirect("/submit");
  }
});

// PASSPORT CONFIGURATION

// Local strategy using async/await for password comparison
passport.use(
  "local",
  new LocalStrategy(async (username, password, cb) => {
    try {
      const result = await pool.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length === 0) {
        return cb(null, false, { message: "User not found" });
      }
      const user = result.rows[0];
      // Compare passwords using async/await
      const valid = await bcrypt.compare(password, user.password);
      if (valid) {
        return cb(null, user);
      } else {
        return cb(null, false, { message: "Incorrect password" });
      }
    } catch (err) {
      return cb(err);
    }
  })
);

// Google OAuth2 strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        process.env.NODE_ENV === "production"
          ? "https://secrets-project-backend.vercel.app/auth/google/secrets"
          : "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await pool.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          // Insert new user with a placeholder password (e.g., "google") and return the new user
          const newUser = await pool.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Serialize only the user id into the session
passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

// Deserialize user by looking up the user by id in the database
passport.deserializeUser(async (id, cb) => {
  try {
    const result = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    cb(err);
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
