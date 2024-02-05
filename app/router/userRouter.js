const express = require('express');
const userRouter =  express.Router();
const userController = require("../controller/userController.js");
const verifyToken = require('../middleware/auth.js');
const multer  = require('multer')
const upload = require('../middleware/uploadImage');
const validation = require('../services/joiValidation')
const userSchema = require('../schema/userBody');

// CUSTUM TYPE/SCHEMA
/**
 * A user
 * @typedef {object} User
 * @property {string} firstname - prénom
 * @property {string} lastname - nom
 * @property {string} username - pseudo
 * @property {string} email - email
 * @property {string} password - mot de pase
 * @property {string} image_path - chemin image de profil
 * @property {string} role - rôle
 * 
 */


/**
 * GET /api/users
 * @summary  génère tous les utilisateurs
 * @type {user}
 * @security TokenAuth
 * @tags User
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
userRouter.get('/users', verifyToken, userController.getUsers);

/**
 * GET /api/user/{id}
 * @summary  génère un utilisateur en fonction de son id
 * @type {user}
 * @tags User
 * @security TokenAuth
 * @return {object} 200 - post response
 * @param {number} id.path.required - id en entrée
 * @return {object} 404 - Unexpected error
 */


/**
 * GET /api/user/{id}
 * @summary  génère un utilisateur en fonction de son id
 * @type {user}
 * @tags User
 * @security TokenAuth
 * @return {object} 200 - post response
 * @param {number} id.path.required - id en entrée
 * @return {object} 500 - Unexpected error
 */

userRouter.get('/user/:id', verifyToken, userController.getOneUser);





/**
 * PATCH /api/user/{id}
 * @summary  modifie les données  d'un utilisateur en fonction de son id
 * @type {user}
 * @tags User
 * @security TokenAuth
 * @return {object} 200 - post response
 * @param {number} id.path.required - id en entrée
 * @return {object} 500 - Unexpected error
 */
userRouter.patch('/user/:id',  validation.check(userSchema.userUpdate(), "body") ,verifyToken, userController.modifyUser); /** here */




// CUSTUM TYPE/SCHEMA
/**
 * A user
 * @typedef {object} userProfile
 * @property {string} image_path - chemin image de profil

 * 
 */

/**
 * PATCH /api/user/{id}/profile
 * @summary  modifie les données  d'un utilisateur en fonction de son id
 * @type {user}
 * @tags User
 * @security TokenAuth
 * @return {object} 200 - formData response
 * @param {userProfile} request.body.required - - multipart/form-data
 * @param {number} id.path.required - id en entrée
 * @return {object} 500 - Unexpected error
 */
userRouter.patch('/user/:id/profile', verifyToken, upload.single('file'), userController.updatePicture)


/**
 * DELETE /api/user/{id}
 * @summary  supprime un utilisateur en fonction de son id
 * @type {user}
 * @tags User
 * @security TokenAuth
 * @return {object} 200 - post response
 * @param {number} id.path.required - id en entrée
 * @return {object} 500 - Unexpected error
 */
userRouter.delete('/user/:id', verifyToken, userController.deleteUser);


module.exports = userRouter