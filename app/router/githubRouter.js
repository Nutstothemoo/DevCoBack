const express = require('express');
const githubRouter =  express.Router();

const GithubController = require('../controller/GithubController.js')

githubRouter.get("/getAccessToken", GithubController.getAccessToken); 
githubRouter.get("/getUserData", GithubController.getUserdata);
githubRouter.get("/getUserRepos", GithubController.getUserRepos);
githubRouter.get('/getUserOrgs', GithubController.getUserOrgs)

module.exports = githubRouter;