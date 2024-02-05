const pool = require('../services/dbClient');

 //define the core model class that will help create other models

class Core {
tableName;

   constructor() {      
   }
   /**
    * Récupération par identifiant
    * @param {number|number[]} id identifiant ou liste d'identifiants
    * @returns un enregistrement ou une liste d'enregistrement
    */
   async findByPk(id) {
      try {
         const preparedQuery = {
            text: `SELECT * FROM "${this.tableName}" WHERE id = $1`,
            values: [id],
         };
   
         const result = await pool.query(preparedQuery);
   
         if (!result.rows[0]) {
            return null;
         }
   
         return result.rows[0];
      } catch (error) {
         console.error(`Error in findByPk() : ${error.message}`)
            throw error;
      }
      
   }

   static async findAll(params) {
      try {
         let filter = '';
      const values = [];

      // params? verify if params exists,then if params.$where exists
      if (params?.$where) {
         const filters = []; //  initialize the table which will contain every WHERE conditions 
         let indexPlaceholder = 1; // initialize a counter to handle prepared queries $1,$2...

         // Object.entries decomposes the object into a table which result will be like this : [ key , value ] 
         Object.entries(params.$where).forEach(([param, value]) => { 
               // verify if params is equal to $or( to handle the case we want  OR in the WHERE condition)
               if (param === '$or') {
                  const filtersOr = [];
                  // we decompose in case the value is an object(to create a more complex  query)                  
                  Object.entries(value).forEach(([key, val]) => { // parfor example ["city_id",2]
                     filtersOr.push(`"${key}" = $${indexPlaceholder}`); // we add  $1 to first iteration, then $2 ,then $3 and so on..
                     values.push(val); // then we push the value (example 2)
                     indexPlaceholder += 1; // we increment the counter $1, $2...
                  });
                  filters.push(`(${filtersOr.join(' OR ')})`); // we add OR in the query if there were $or in the condition at the begining
               
               } else {
                  filters.push(`"${param}" = $${indexPlaceholder}`); 
                  values.push(value); // we add the value
                  indexPlaceholder += 1; // we increment the counter to handle $1, $2...
               }
         });
         filter = `WHERE ${filters.join(' AND ')}`;
      }

      const preparedQuery = {
         text: `
               SELECT * FROM "${this.tableName}"
               ${filter}
               LIMIT 20 
         `, // le LIMIT 20 a été ajouté pour pas faire planter la VM
         values,
      };

      const result = await pool.query(preparedQuery);
      return result.rows;
      } catch (error) {
         console.error(`Error in findAll() : ${error.message}`)
            throw error;
      }
      
   }

   async create(inputData) {
      try {
         const fields = [];
      const placeholders = [];
      const values = [];
      let indexPlaceholder = 1;

      Object.entries(inputData).forEach(([prop, value]) => {
         fields.push(`"${prop}"`);
         placeholders.push(`$${indexPlaceholder}`);
         indexPlaceholder += 1;
         values.push(value);
      });

      const preparedQuery = {
         text: `
               INSERT INTO "${this.tableName}"
               (${fields})
               VALUES (${placeholders})
               RETURNING *
         `,
         values,
      };
      const result = await pool.query(preparedQuery);
      const row = result.rows[0];

      return row;
      } catch (error) {
         console.error(`Error in create() : ${error.message}`)
            throw error;
      }
      
   }
   // query that return  rows of a tablename where the condition in WHERE is met
   async findByField(field, param) {
      try {
         const preparedQuery = {
            text: `SELECT  * FROM "${this.tableName}" WHERE ${field} = $1`,
            values: [param],
        };
        
        const result = await pool.query(preparedQuery);
        
        if (!result.rows[0]) {
            return null;
        }
        
        return result.rows[0];
      } catch (error) {
         console.error(`Error in findByField() : ${error.message}`)
         throw error;
      }
      
  }

   async update(id , inputData) {
      try {
         const fieldsAndPlaceholders = [];
         let indexPlaceholder = 1;
         const values = [];
   
         Object.entries(inputData).forEach(([prop, value]) => {
            fieldsAndPlaceholders.push(`"${prop}" = $${indexPlaceholder}`);
            indexPlaceholder += 1;
            values.push(value);
         });
         
         values.push(id);
   
         const preparedQuery = {
            text: `
                  UPDATE "${this.tableName}" SET
                  ${fieldsAndPlaceholders}
                  WHERE id = $${indexPlaceholder}
                  RETURNING *
            `,
            values,
         };
         const result = await pool.query(preparedQuery);
         const row = result.rows[0];
   
         return row;
      } catch (error) {
         console.error(`Error in update() : ${error.message}`)
            throw error;
      }
     
   }

   async delete(id) {
      try {
         const result = await pool.query(`DELETE FROM "${this.tableName}" WHERE id = $1`, [id]);
      return !!result.rowCount;
      } catch (error) {
         console.error(`Error in delete() : ${error.message}`)
            throw error;
      }
      
   }
}

module.exports = Core;
