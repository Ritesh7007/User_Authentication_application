// set up
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

mongoose.connect("mongodb://127.0.0.1:27017/authdb")
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log(err));

// token blacklist
const tokenBlacklist = [];  

// user Schema with password
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: {type: String, enum: ["admin", "user"], default: "user"}
});

const User = mongoose.model("User", userSchema);

// password hashing with bcrypt
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({ name, email, password: hashedPassword, role });
    await newUser.save();

    res.status(201).json({ msg: "User created successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// login with bcrypt and JWT
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ msg: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ msg: "Invalid credentials" });

  const token = jwt.sign({ id: user._id }, "secretkey", { expiresIn: "1h" });
  res.json({ msg: "Login successful", token });
});

// middleware for protected routes
function auth(req, res, next) {
  const token = req.header("Authorization")?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ msg: "No token, access denied" });

  //blacklist
  if(tokenBlacklist.includes(token))
  {
    return res.status(403).json({msg: "Token has been logged out"});
  }

  try {
    const verified = jwt.verify(token, "secretkey");
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).json({ msg: "Invalid token" });
  }
}

app.get("/profile", auth, async (req, res) => {
  const user = await User.findById(req.user.id).select("-password");
  res.json(user);
});

app.get("/admin", auth, async (req, res) =>
{
    if(req.user.role !== "admin")
    {
        return res.status(403).json({msg: "Access deniel: Admins only"});
    }
    res.json({msg: "Welcome Admin, you have full access."});
});

app.post("/logout", auth, (req, res) =>
{
    const token = req.header("Authorization")?.replace("Bearer", "");
    if(!token)
    {
        return res.status(401).json({msg: "No token provided"});
    }
        tokenBlacklist.push(token);
        res.json({msg: "Logged out Successfully"});
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));
