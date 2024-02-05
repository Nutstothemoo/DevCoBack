const Joi = require('joi')

// user's schema
const userSchema = {

    // user registration schema
    register(){
        return Joi.object({ 
            username: Joi.string().max(30).required(), 
            email: Joi.string().email().required(), 
            password: Joi.string().min(6).max(30).required(), 
            passwordConfirm: Joi.string().min(6).max(30).required(),        
        });
    },

    // user login schema
    login(){
        return Joi.object({            
            email: Joi.string().email().required(), 
            password: Joi.string().max(30).required()           
        });
    },

    // user update schema
     userUpdate(){
       return  Joi.object({
                firstname: Joi.string().allow("", null), 
                lastname: Joi.string().allow("", null), 
                username: Joi.string().allow("", null),
                email: Joi.string().email().allow("", null),
                image_path: Joi.string().allow("", null),                
            })
     },

     // user update profile image schema
     updateProfile(){
        Joi.object({
            image_path: Joi.string(), 
        })
     }
}
module.exports = userSchema


// module.exports = Joi.object({
//     id:Joi.number().integer().min(1),
//     firstname: Joi.string().allow('', null).min(3).max(30), 
//     lastname: Joi.string().allow('', null).min(3).max(30), 
//     username: Joi.string().min(3).max(30), 
//     email: Joi.string().min(3).max(30).required(), 
//     password: Joi.string().min(3).max(30), 
//     passwordConfirm: Joi.string().min(3).max(30), 
//     image_path: Joi.string(), 
//     role: Joi.string()
// });