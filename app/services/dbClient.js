

//  Comme pour Client les informations de connexion
//   sont lu soit directement à partir de l'env soit donnée en paramêtre

require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool();

module.exports = pool;