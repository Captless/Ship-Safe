const express = require("express");
const app = express();

app.use((req, res, next) => {
  if (!req.headers.authorization) return res.status(401).end();
  next();
});

app.get("/api/users", (req, res) => {
  res.json([]);
});
