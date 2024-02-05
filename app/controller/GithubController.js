const { response } = require('express');
const User = require('../model/userModel.js');
const fetch = (...args) =>
import(`node-fetch`).then(({ default: fetch }) => fetch(...args));
require('dotenv').config();

const GithubController = {
  getAccessToken: async (req, res) => {
    
    const params = `?client_id=${process.env.GITHUB_CLIENT_ID}&client_secret=${process.env.GITHUB_CLIENT_SECRET}&code=${req.query.code}`;
    await fetch(`https://github.com/login/oauth/access_token${params}`, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
      },
    }).then((response) => {
        return response.json();
      }).then((data) => {
        res.json(data);
      });
  },
  getUserdata: async (req, res) => {
    req.get('Authorization'); // Bearer ACCESSTOKEN
    await fetch('https://api.github.com/user', {
      method: 'GET',
      headers: {
        "Authorization": req.get('Authorization'),
      },
    }).then((response) => {
        return response.json();
      }).then((data) => {
        res.status(200).json(data);
      });
  },
  getUserRepos:  async (req, res) => {
    req.get('Authorization'); // Bearer ACCESSTOKEN
    await fetch('https://api.github.com/user/repos', {
      method: 'GET',
      headers: {
        "Authorization": req.get('Authorization'),
      },
    }).then((response) => {
        return response.json();
      }).then((data) => {
        res.status(200).json(data);
      });
  },
  getUserOrgs:  async (req, res) => {
    req.get('Authorization'); // Bearer ACCESSTOKEN
    await fetch('https://api.github.com/user/orgs', {
      method: 'GET',
      headers: {
        "Authorization": req.get('Authorization'),
      },
    }).then((response) => {
        return response.json();
      }).then((data) => {
        res.status(200).json(data);
      });
  },
};
module.exports = GithubController;
