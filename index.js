const express = require("express");
const session = require("express-session");
const passport = require("passport");
const dotenv = require("dotenv");
dotenv.config();
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const User = require("./models/User");
const { connectDB } = require("./config/database");
const cors = require("cors");
const helmet = require("helmet");
const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  cors({
    origin: process.env.FRONT_END,
  })
);
app.use(helmet());
app.use(helmet.crossOriginResourcePolicy({ policy: "cross-origin" }));

app.use(
  session({
    secret: process.env.KEY,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Passport Configuration
passport.use(
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      try {
        const user = await User.findOne({ email });
        if (!user) {
          return done(null, false, {
            message: "Invalid email or password",
            success: false,
          });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
          return done(null, false, {
            message: "Invalid email or password",
            success: false,
          });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  User.findById(id, (err, user) => {
    done(err, user);
  });
});

// Routes
app.post("/login", passport.authenticate("local"), (req, res) => {
  if (!req.user) {
    // Authentication failed; handle it as needed.
    return res.status(401).json({ message: "Authentication failed" });
  }

  // Store user information in the session
  req.session.user = req.user;

  // Optionally, you can clear sensitive data from the user object before sending it in the response.
  // For example, you might want to remove the password hash.
  const sanitizedUser = { ...req.user.toObject() };
  delete sanitizedUser.password;

  // Send a response to the client with a success message and the user data.
  res.json({ message: "Login successful", user: sanitizedUser, success: true });
});
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;

  // Check if the email is already in use
  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.json({ message: "Email already registered", success: false });
  }

  // Hash the password before saving it
  const hashedPassword = await bcrypt.hash(password, 10);

  // Create a new user
  const newUser = new User({
    email,
    password: hashedPassword,
  });

  try {
    await newUser.save();
    return res.json({
      message: "User registered successfully",
      success: true,
    });
  } catch (error) {
    return res.json({ message: "Error registering user", success: false });
  }
});

app.post("/logout", (req, res) => {
  req.logout();
  req.session.destroy((err) => {
    if (err) {
      console.error("Error destroying session:", err);
    }
    return res.json({ message: "Logout successful", success: true });
  });
});

connectDB().then(() => {
  app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
  });
});
