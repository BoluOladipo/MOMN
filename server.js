require("dotenv").config();
const express = require("express");
const http = require("http");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(express.json());
app.use(express.static("public"));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch(console.error);

/* MODELS */
const User = mongoose.model("User", new mongoose.Schema({
  email: String,
  password: String
}));

const Message = mongoose.model("Message", new mongoose.Schema({
  sender: String,
  text: String,
  media: String,
  mediaType: String,
  seen: { type: Boolean, default: false },
  time: { type: Date, default: Date.now }
}));


/* SIGNUP */
app.post("https://momn-2pn6.onrender.com", async (req, res) => {
  const { email, password } = req.body;

  const count = await User.countDocuments();
  if (count >= 2) return res.status(403).send("Limit reached");

  const exists = await User.findOne({ email });
  if (exists) return res.status(409).send("User exists");

  const hash = await bcrypt.hash(password, 10);
  await User.create({ email, password: hash });
  res.sendStatus(201);
});

/* LOGIN */
app.post("https://momn-2pn6.onrender.com", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.sendStatus(401);

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.sendStatus(401);

  const token = jwt.sign({ email }, process.env.JWT_SECRET);
  res.json({ token, email });
});

/* USER COUNT */
app.get("https://momn-2pn6.onrender.com", async (req, res) => {
  const count = await User.countDocuments();
  res.json({ count });
});

/* MESSAGES */
app.get("https://momn-2pn6.onrender.com", async (req, res) => {
  jwt.verify(req.headers.authorization, process.env.JWT_SECRET);
  const msgs = await Message.find().sort({ time: 1 });
  res.json(msgs);
});



/* SOCKET */
io.use((socket, next) => {
  try {
    socket.user = jwt.verify(socket.handshake.auth.token, process.env.JWT_SECRET);
    next();
  } catch {
    next(new Error("Unauthorized"));
  }
});

io.on("connection", socket => {

  socket.on("sendMedia", async ({ data, type }) => {
  const msg = await Message.create({
    sender: socket.user.email,
    media: data,
    mediaType: type === "img" ? "img" : "video"
  });
  io.emit("receive", msg);
});

  Message.updateMany(
    { sender: { $ne: socket.user.email }, seen: false },
    { seen: true }
  ).exec();

  socket.on("send", async text => {
    const msg = await Message.create({
      sender: socket.user.email,
      text
    });
    io.emit("receive", msg);
  });

  socket.on("typing", () => socket.broadcast.emit("typing"));
  socket.on("stopTyping", () => socket.broadcast.emit("stopTyping"));
});

const PORT = parseInt(process.env.PORT) || 3000; // fallback to 3000 locally

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

