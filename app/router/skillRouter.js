const express = require('express');
const skillRouter =  express.Router();
const skillController = require("../controller/skillController.js")



// CUSTUM TYPE/SCHEMA
/**
 * A Skill 
 * @typedef {object} Skill
 * @property {string} name - name of the skill
 * @property {number} level - feed link
 */


/**
 * GET /api/skills
 * @summary  récupère toutes les compétences 
 * @type {Skill}
 * @security TokenAuth
 * @tags Skill
 * @return {object} 200 - Skill response
 * @return {object} 500 - Unexpected error
 */

skillRouter.get('/skills', skillController.getSkills);

skillRouter.post("/user/:id/skill", skillController.addSkill);





/**
 * GET /api/skill/{id}
 * @summary   récupère une compétence en fonction de l'id
 * @security TokenAuth
 * @tags Skill
 * @param {number} id.path.required -  id d'une compétence en entrée
 * @return {object} 200 - feed response
 * @return {object} 500 - Unexpected error
 */
skillRouter.get("/skill/:id", skillController.getOneSkill);




/**
 * PATCH /api/user/{user_id}/skill/{id}
 * @summary  permet à l'utilisateur de modifier l'une de ses compétences  
 * @type {Skill}
 * @security TokenAuth
 * @tags Skill
 * @param {number} id.path.required -  id d'une compétence en entrée
 * @param {number} user_id.path.required -  id d'un utilisateur en entrée
 * @return {object} 200 - feed response
 * @return {object} 500 - Unexpected error
 */
skillRouter.patch("/user/:user_id/skill/:id", skillController.modifySkill);


/**
 * DELETE /api/user/{user_id}/skill/{id}
 * @summary  permet à l'utilisateur de supprimer l'une de ses compétences  
 * @type {Skill}
 * @security TokenAuth
 * @tags Skill
 * @param {number} id.path.required -  id d'une compétence en entrée
 * @param {number} user_id.path.required -  id d'un utilisateur en entrée
 * @return {object} 200 - feed response
 * @return {object} 500 - Unexpected error
 */

skillRouter.delete("/user/:user_id/skill/:id", skillController.deleteSkill);

//skillRouter.get('/user/:user_id/skills', skillController)
//skillRouter.get('/user/:user_id/skill/:id', skillController)

module.exports = skillRouter;
