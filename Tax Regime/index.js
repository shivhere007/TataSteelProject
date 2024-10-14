import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import flash from "connect-flash";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Middleware setup
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(flash());

// Session management
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 1000 * 60 * 60, // 1 hour
      httpOnly: true,
    },
  })
);

// Initialize passport and session
app.use(passport.initialize());
app.use(passport.session());

// Passport Local Strategy for login
passport.use(
  new LocalStrategy(
    { usernameField: "aadharno", passwordField: "password" },
    async (aadharno, password, done) => {
      try {
        // Fetch user from database
        const userResult = await db.query(
          "SELECT * FROM users WHERE aadharno = $1",
          [aadharno]
        );
        if (userResult.rows.length > 0) {
          const user = userResult.rows[0];
          const isPasswordMatch = await bcrypt.compare(password, user.password);
          if (isPasswordMatch) {
            return done(null, user); // Authentication successful
          } else {
            return done(null, false, { message: "Incorrect password" });
          }
        } else {
          return done(null, false, { message: "User not found" });
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

// Serialize user information into session
passport.serializeUser((user, done) => {
  done(null, user.aadharno);
});

// Deserialize user from session
passport.deserializeUser(async (aadharno, done) => {
  try {
    const userResult = await db.query(
      "SELECT * FROM users WHERE aadharno = $1",
      [aadharno]
    );
    if (userResult.rows.length > 0) {
      done(null, userResult.rows[0]);
    } else {
      done(null, false);
    }
  } catch (err) {
    done(err, false);
  }
});

// Custom middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}

// Global middleware to pass flash messages to views
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.error = req.flash("error"); // for passport's default error
  next();
});

// Routes
app.get("/", (req, res) => {
  res.render("login.ejs", { message: req.flash("error") });
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// Registration route
app.post("/createuser", async (req, res) => {
  const {
    aadharno,
    username,
    email,
    contactno,
    department,
    password,
    confirmpassword,
  } = req.body;

  if (
    !aadharno ||
    !username ||
    !email ||
    !contactno ||
    !department ||
    !password ||
    !confirmpassword
  ) {
    return res.status(400).send("All fields are required");
  }

  if (password !== confirmpassword) {
    return res.status(400).send("Passwords do not match");
  }

  try {
    const userExists = await db.query(
      "SELECT * FROM users WHERE aadharno = $1 OR email = $2",
      [aadharno, email]
    );
    if (userExists.rows.length > 0) {
      return res.status(400).send("Email already in use! Try logging in.");
    } else {
      const hash = await bcrypt.hash(password, saltRounds);
      await db.query(
        "INSERT INTO users (aadharno, username, email, contactno, department, password) VALUES ($1, $2, $3, $4, $5, $6)",
        [aadharno, username, email, contactno, department, hash]
      );
      return res.status(201).send("User registered successfully");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

// Login route using Passport
app.post(
  "/submit",
  passport.authenticate("local", {
    successRedirect: "/index",
    failureRedirect: "/",
    failureFlash: "Your login attempt was not successful. Please try again.",
  })
);

// Protected route (Index page)
app.get("/index", isAuthenticated, (req, res) => {
  res.render("index.ejs", { user: req.user });
});

// Route for "My Tax Regime"
app.get("/my-tax-regime", isAuthenticated, async (req, res) => {
  res.render("mytax.ejs", { user: req.user });
});

// Route for "Report"
app.get("/report", isAuthenticated, async (req, res) => {
  const { fromDate, toDate } = req.query;
  let records = [];

  try {
    if (fromDate && toDate) {
      // Query the database for records within the date range
      const query = `
          SELECT * FROM my_tax_regime 
          WHERE submittedat BETWEEN $1 AND $2
          ORDER BY submittedat DESC;
        `;
      const result = await db.query(query, [fromDate, toDate]);
      records = result.rows; // Store records fetched from the database
    }
    res.render("report.ejs", { user: req.user, records });
  } catch (error) {
    console.error("Error fetching tax regime report:", error);
    res.status(500).send("Server error");
  }
});

// Switch option route
app.post("/submit-switch-option", isAuthenticated, async (req, res) => {
  const { aadharno, username, department, switchOption } = req.body;

  if (!req.body.readDocs || !req.body.oneSwitch) {
    return res
      .status(400)
      .send("You must agree to the terms before submitting.");
  }

  try {
    const trimmedAadhar = aadharno.trim();
    const userResult = await db.query(
      "SELECT * FROM users WHERE aadharno = $1",
      [trimmedAadhar]
    );

    if (userResult.rows.length > 0) {
      await db.query(
        "UPDATE users SET switchoption = $1, submittedat = NOW() WHERE aadharno = $2",
        [switchOption, trimmedAadhar]
      );

      await db.query(
        "INSERT INTO my_tax_regime (aadharno, username, department, switchoption, submittedat) VALUES ($1, $2, $3, $4, NOW())",
        [trimmedAadhar, username, department, switchOption]
      );

      res.send("Submitted successfully");
    } else {
      res.status(404).send("User not found");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Server error");
  }
});

// Logout route
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    req.session.destroy((err) => {
      if (err) {
        return next(err);
      }
      res.redirect("/"); // Redirect to login page after logout
    });
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}.`);
});
