const cors = require("cors");
const express = require("express");
const {
  userRouter,
  authRouter,
  postRouter,
  feedRouter,
  skillRouter,
  githubRouter,
} = require("./app/router");

require("dotenv").config();
const app = express();
const port = process.env.PORT || 3001;
const bodyParser = require("body-parser");


// server initialization

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.json());
app.use(cors());
app.enable("trust proxy")


// SWAGGER
const expressJSDocSwagger = require("express-jsdoc-swagger");
const { arrayParser } = require("pg-types");

const options = {
  info: {
    version: "1.0.0",
    title: "Devboard",
    description: "My API with Swagger documentation",
    license: {
      name: "MIT",
    },
  },
  //Chemin de la doc
  swaggerUIPath: "/devboard",
  security: {
    basic: {
      type: "http",
      scheme: "basic",
      bearerFormat: "JWT "
    }
  },
  security: {
    TokenAuth : {
      type: 'http',
      scheme: 'bearer'
    }
  },
  baseDir: __dirname,
  // Glob pattern to find your jsdoc files (multiple patterns can be added in an array)
  filesPattern: "./**/*.js",
};

expressJSDocSwagger(app)(options);

// REDIRECTION ROUTER

app.use("/api", userRouter);
app.use("/api", authRouter);
app.use("/api", postRouter);
app.use("/api", feedRouter);
app.use("/api", skillRouter);
app.use("/api", githubRouter);

module.exports = app
app.listen(port, () => {
  console.log(`Server ready:  http://localhost:${port}`);
});
