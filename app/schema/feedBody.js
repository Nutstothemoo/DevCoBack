const Joi = require('joi')

const feedSchema = {
    addFeed(){
        return Joi.object({ 
            title: Joi.string().min(3).max(30).required(), 
            url: Joi.string().uri().required(), 
        });
    },
    updateFeed(){
        return Joi.object({ 
            title: Joi.string().min(3).max(30), 
            url: Joi.string().uri(), 
        });
    }
}
module.exports = feedSchema
