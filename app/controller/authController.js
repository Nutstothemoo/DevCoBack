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
        console.log("req.body :", req.body)
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
        

       //  verify if email and or username already exist in the database if so, send a error message 
        if(userEmail ){
            res.status(404).json('user with that email already exist')
        } else if( userUsername) {
            res.status(404).json('user with that  username already exist')
        }
        //else create user and insert it into database
        else{
            const newUser = await savedUser.create({
                username: req.body.username,
                email: req.body.email,
                password: hashedPassword,
            });
            // get the token 
            const token = jwt.sign({id: newUser._id}, process.env.JWT_SECRET);
            //send user  and token 
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
          // generate an instance of User class   
            const user = new User();
             // get a user by its email 
            const userAuth = await user.findByField("email", req.body.email);  
            console.log(userAuth)
            //const userAuth = await User.findAll({ $where: {email:req.body.email} });
            
            
            // if no user is found with that email an error message is send 
            if (!userAuth) return res.status(400).json( {msg: " L'utilisateur n'existe pas"})
            // password comparison between password  user provided and the password of an user registered

            // if passwords dont match an error is send 
                if(await bcrypt.compare(req.body.password, userAuth.password)){
                    //get token 
                const token = jwt.sign({id: user._id}, process.env.JWT_SECRET);
                // password is deleted before it is send 
           
            delete userAuth.password;
            // token and user send 
            res.status(200).json({token, userAuth}); 

            //else a 404 status is send 
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