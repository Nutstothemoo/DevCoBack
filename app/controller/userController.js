const User = require('../model/userModel.js')
const bcrypt = require('bcrypt')
//const upload = require('../middleware/uploadImage');
//const datamapper = require('../model/updatePicture')
const userController = {
   /**
    *   generate all users
    * @param {*} req 
    * @param {*} res 
    */
   getUsers: async (req, res)=>{
      try {
        // get all users from User class 
         const users = await User.findAll()
         res.status(200).json(users)

      } catch(err) {
         //
         res.status(404).json({message: err.message})
      }
      
   },  
   
   /**
    *  generate one user by its email
    * @param {*} req 
    * @param {*} res 
    */
   getOneUserbyEmail: async (req,res) => {
      try {
         // get an instance of a user
      const user = new User();
      // find user by its email
      const newUser = await user.findByEmail({});
      // user response
      res.status(200).json(newUser)
         
      } catch(err) {
         // error response
         res.status(400).json({message: err.message})
      }
   },
   /**
    * generate one user
    * @param {*} req 
    * @param {*} res 
    */
   getOneUser: async (req,res) => {
      try {
         // get an instance of a user
      const user = new User();
      // find user by its id 
      const newUser = await user.findByPk(req.params.id);
      // user response
      res.status(200).json(newUser)

      } catch(err) {
         //error response
         res.status(400).json({message: err.message})
      }
   },

   /**
    * update user info
    * @param {*} req 
    * @param {*} res 
    * @returns 
    */
   modifyUser: async (req, res)=> {   
      try {
         // get an instance of user
   const user = new User()
   // get user by id        
         const userByEmail = await user.findByField("email", req.body.email);
         const userByUsername = await user.findByField("username", req.body.username)
        //console.log( userByEmail.id != req.params.id)
         if(userByEmail && userByEmail.id != req.params.id){
            return res.status(409).json({ error: 'Email address already in use' });
            
         }
         if(userByUsername && userByUsername.id != req.params.id){
            return res.status(409).json({ error: 'username address already in use' });
         }
         
         console.log(req.params.id);
         console.log(req.body );
         const newUser = await user.update( req.params.id, req.body);
         res.status(200).json(newUser)        

      } catch(err) {
         console.log(err)
         res.status(400).json({message: err.message})
      }
   },

   /**
    * to delete user 
    * @param {*} req 
    * @param {*} res 
    */
   deleteUser: async (req,res) => {
      try {         
         const user = new User();
         const newUser = await user.delete(req.params.id);
         res.status(200).json(newUser)
      } catch(err) {
         res.status(400).json({message: err.message})
      }
   },

   /**
    * update user's profile picture
    * @param {*} req 
    * @param {*} res 
    */
   updatePicture: async (req, res)=>{
      console.log(req.file);
      try {
         const user = new User()
         const userProfile = await user.updatePicture(`${req.file.filename}`, req.params.id)
         const newUser = await user.findByPk(req.params.id)
         console.log(userProfile);
         res.status(200).json(newUser)
      } catch (error) {
         res.status(400).json({message: err.message})
      }
   }
}
module.exports = userController; 