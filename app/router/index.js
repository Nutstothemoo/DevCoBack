const userRouter = require("./userRouter");
const authRouter = require("./authRouter");
const postRouter = require("./postRouter.js");
const feedRouter = require("./feedRouter.js");
const skillRouter = require("./skillRouter.js");
const githubRouter =require('./githubRouter')

module.exports = {
  userRouter,
  authRouter,
  postRouter,
  feedRouter,
  skillRouter,
  githubRouter
};
