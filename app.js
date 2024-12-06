require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

app.use(express.json());

const User = require("./models/User");

app.get("/", (req, res) => {
  res.status(200).json({ msg: "Welcome to the API" });
});

app.get("/user", checkToken, async (req, res) => {
  const user = await User.findById(req.user.id, "-password");

  if (!user) {
    return res.status(404).json({ msg: "User was not found!" });
  }

  res.status(200).json({ user });
});

function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ msg: "Access denied!" });

  try {
    const secret = process.env.SECRETKEY;

    const decoded = jwt.verify(token, secret);

    req.user = decoded;
    next();
  } catch (err) {
    res.status(400).json({ msg: "Invalid token!" });
  }
}

//registrar user
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmPass } = req.body;

  const requiredFields = [
    { field: "name", message: "Name is required!" },
    { field: "email", message: "Email is required!" },
    { field: "password", message: "Password is required!" },
    { field: "confirmPass", message: "Password confirmation is required!" },
  ];

  for (const { field, message } of requiredFields) {
    if (!req.body[field]) {
      return res.status(422).json({ msg: message });
    }
  }

  if (confirmPass !== password) {
    return res.status(422).json({ msg: "Passwords do not match." });
  }

  const userExist = await User.findOne({ email: email });
  if (userExist) {
    return res.status(422).json({ msg: "This email is already being used" });
  }

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const user = new User({
    name,
    email,
    password: passwordHash,
  });

  try {
    await user.save();
    res.status(201).json({ msg: "User created with success!" });
  } catch (error) {
    res.status(500).json({ msg: "A server error occurred, try again later!" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;

  const requiredFields = [
    { field: "email", message: "Email is required!" },
    { field: "password", message: "Password is required!" },
  ];

  for (const { field, message } of requiredFields) {
    if (!req.body[field]) {
      return res.status(422).json({ msg: message });
    }
  }

  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ msg: "User was not found!" });
  }

  const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) {
    return res.status(422).json({ msg: "Invalid password!" });
  }

  try {
    const secretKey = process.env.SECRETKEY;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secretKey
    );

    res.status(200).json({ msg: "Authentication was successful", token });
  } catch (error) {
    res.status(500).json({ msg: "A server error occurred, try again later!" });
  }
});

//credenciais
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASS;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.qxcsd.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`
  )
  .then(() => {
    app.listen(3000);
    console.log("Connected to the Database!");
  })
  .catch((err) => console.log("Failed to connect to MongoDB", err));
