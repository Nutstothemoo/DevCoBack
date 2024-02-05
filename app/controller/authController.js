const User = require("../model/userModel.js");
const bcrypt = require('bcrypt');
require('dotenv').config();
const jwt = require('jsonwebtoken');

const authController = {

    /**
     * user registration 
     * @param {*} req 
     * @param {*} res 
     * @returns 
     */
    registerUser: async (req, res) => {
    try {
        // verify if the password and the password confirmation are the same
        if (req.body.password !== req.body.passwordConfirm) return res.status(400).json( {msg: 'les mots de passe  ne correspondent pas'})

        const salt = await bcrypt.genSalt(10);

        // password hashing
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        // generate an instance of User class 
        const savedUser =  new User();

        // get a user by its email 
        const userEmail = await savedUser.findByField("email",req.body.email);
        // get a user by its username
        const userUsername = await savedUser.findByField("username", req.body.username)
        

            if(userEmail){
                res.status(409).json('User with that email already exists');
            } else if(userUsername) {
                res.status(409).json('User with that username already exists');
            }
        else{
            const newUser = await savedUser.create({
                username: req.body.username,
                email: req.body.email,
                password: hashedPassword,
            });
            const token = jwt.sign({id: newUser._id}, process.env.JWT_SECRET);
            delete newUser.password;
            res.status(201).json({token, newUser}); 
        }
        
        // send error if something went wrong
        } catch (err) {
            console.error(err);
            res.status(500).json({ error: err.message });
        }
    },
    

    /**
     * user login
     * @param {*} req 
     * @param {*} res 
     * @returns 
     */
    loginUser: async(req,res)=>{
        try{
            const user = new User();

            const userAuth = await user.findByField("email", req.body.email);  

            if (!userAuth) return res.status(400).json( {msg: " L'utilisateur n'existe pas"})

                if(await bcrypt.compare(req.body.password, userAuth.password)){
                   const token = jwt.sign({id: user._id}, process.env.JWT_SECRET);
      
           
            delete userAuth.password;

            res.status(200).json({token, userAuth}); 
                }else {
                    return res.status(400).json( {msg: "Le mot de passe est incorrect !"})
                }
            
        } catch(err) {
            console.error(err);
            res.status(500).json({error: err.message})
        }
    }
};

module.exports = authController;