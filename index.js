const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const app = express();
dotenv.config();
// import routes
const authRoutes = require("./routes/auth");
const dashboardRoutes = require("./routes/dashboard");
const verifyToken = require("./routes/validate-token");

// middlewares
app.use(express.json()); // for body parser

mongoose.connect(
            process.env.DB_CONNECT,
            { useNewUrlParser: true, useUnifiedTopology: true },
            ()=>console.log("connected to db"));

//route middleware
app.use("/api/user",appRoutes);
// this route is protected with token
app.use("/api/dashboard", verifyToken, dashboardRoutes);

app.listen(3000, () => console.log("server is running.."));

