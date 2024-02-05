const express = require("express");
const postRouter = express.Router();
const postController = require("../controller/postController.js");
const verifyToken = require("../middleware/auth.js");
const postSchema = require("../schema/postBody.js");
const validation = require("../services/joiValidation.js");



// CUSTUM TYPE/SCHEMA
/**
 * A post 
 * @typedef {object} Post
 * @property {string} title - titre
 * @property {string} content - contenu
 * @property {number} user_id - id d'un utilisateur
 * @property {string} created_at - date de création d'un post
 * @property {string} updated_at - date de mise à jour d'un post
 * @property {number} like - nombre de like d'un post
 */


/**
 * GET /api/posts
 * @summary  génère tous les posts de tous utilisateurs ainsi que leur photo de profil et leur pseudo 
 * @type {Post}
 * @security TokenAuth
 * @tags Post
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
postRouter.get("/posts", verifyToken, postController.getAllUsersPosts);


/**
 * GET /api/user/{user_id}/posts
 * @summary  génère tous les posts d'un utilisateur ainsi que sa photo de profil et son pseudo en fonction de son id
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} user_id.path.required - id en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */

postRouter.get("/user/:user_id/posts" ,verifyToken, postController.getOneUserPosts);


/**
 * get /api/post/{id}
 * @summary  génère un post à partir de l'id du post
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} id.path.required - id en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */

postRouter.get("/post/:id", verifyToken, postController.getOnePost);

/**
 * post /api/user/{user_id}/post
 * @summary  post crée par un utilisateur
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} user_id.path.required - id en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
postRouter.post("/user/:user_id/post", validation.check(postSchema.addPost(), "body"),verifyToken, postController.addPost);





/**
 * patch /api/user/{user_id}/post/{post_id}
 * @summary  modification de son  post (utilisateur)
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} post_id.path.required - id d'un post en entrée
 * @param {number} user_id.path.required - id d'un utilisateur en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
postRouter.patch("/user/:user_id/post/:id" , validation.check(postSchema.updatePost(), "body"), verifyToken, postController.modifyPost);


/**
 * delete /api/user/{user_id}/post/{post_id}
 * @summary  suppression de son post (utilisateur)
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} post_id.path.required - id d'un post en entrée
 * @param {number} user_id.path.required - id de l'utilisateur en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
postRouter.delete("/user/:user_id/post/:id", verifyToken, postController.deletePost);



/** 
 * get /api/user/{user_id}/like/post/{post_id}
 * @summary  permet de rajouter des likes sur des posts 
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} user_id.path.required - id de l'utilisateur en entrée
 * @param {number} post_id.path.required - id  d'un post en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
postRouter.get('/user/:user_id/like/post/:post_id', verifyToken, postController.addLikesToPost)


/**
 * get /api/likes/post/{post_id}
 * @summary  génère le nombre de likes lié à un post 
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} post_id.path.required - id  d'un post en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
postRouter.get('/likes/post/:post_id', verifyToken, postController.likesCount)


/** 
 * get /api/user/{user_id}/like/posts
 * @summary  génère tous les posts liké par un utilisateur
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} user_id.path.required - id  d'un post en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
postRouter.get('/user/:user_id/like/posts', verifyToken, postController.postsLikedByUser)


/**
 * delete /api/user/{user_id}/like/post/{post_id}
 * @summary  suppression d'un like par un utilisateur
 * @type {Post}
 * @tags Post
 * @security TokenAuth
 * @param {number} post_id.path.required - id en entrée
 * @param {number} user_id.path.required - id de l'utilisateur en entrée
 * @return {object} 200 - post response
 * @return {object} 500 - Unexpected error
 */
postRouter.delete('/user/:user_id/like/post/:post_id', verifyToken,postController.deleteLikesOnPost);



module.exports = postRouter;
 