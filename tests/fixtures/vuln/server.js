const express = require("express");
const cors = require("cors");
const app = express();
app.use(cors({ origin: "*" }));

app.get("/api/admin/users", (req, res) => {
  res.json({ users: [] });
});

app.post("/api/pay", (req, res) => {
  const amount = req.body.amount;
  res.json({ amount });
});

app.listen(3000, () => console.log("dev server"));
