

const Joi = require('joi')

// post schema construction
const postSchema = {
    // schema to add  a post 
    addPost(){
        return Joi.object({ 
            title: Joi.string().min(1).max(80).required(), 
            content: Joi.string().min(1).required(), 
            user_id: Joi.number().integer(),
            like: Joi.number().allow(null),
            created_at: Joi.string().allow('', null),
            updated_at: Joi.string().allow('', null)
        });
    },
    // schema to update a post 
    updatePost(){
        return Joi.object({ 
            title: Joi.string().min(3).max(80), 
            content: Joi.string().min(1), 
            user_id: Joi.number().integer(),
            like: Joi.number(),
            created_at: Joi.string(),
            updated_at: Joi.string()
        });
    }
}
module.exports = postSchema
