const Core = require('./coreModel');

const pool = require('../services/dbClient');

class User extends Core {
    static tableName = 'user';
    
    constructor(){
        super();
        this.tableName = 'user'
    }

    
    async updatePicture(file, id){
        try {
          const sqlQuery = `UPDATE "user" 
                SET        
                image_path = $1        
                WHERE id = $2;
                `;
          const values = [
            file,            
            id
        ];
       
          console.log(values);
          await pool.query(sqlQuery, values);
    
        } catch (error) {
            console.log(error);
        }
      }
   
};



module.exports = User;