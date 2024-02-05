
const Joi = require('joi')


module.exports = Joi.object({
    id: Joi.number().integer().min(1),
    title: Joi.string().min(3).max(30).required(), 
    content: Joi.string(), 
    user_id: Joi.number().integer(),
    like: Joi.number().min(1),
    created_at: Joi.string(),
    updated_at: Joi.string()
}); 