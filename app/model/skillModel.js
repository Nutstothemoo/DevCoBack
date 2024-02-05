const Core = require("./coreModel");

const pool = require("../services/dbClient");

class Skill extends Core {
  static tableName = "skill";
  constructor() {
    super();
    this.tableName = "skill";
  }

  async findSkillByUser(id) {
    const preparedQuery = {
      text: `SELECT "skill".* FROM "skill_id" JOIN "user_has_skill" 
           ON skill.id = user_has_skill.skill_id  
           WHERE user_has_skill.user_id = $1;`,
      values: [id],
    };

    const result = await pool.query(preparedQuery);

    if (!result.rows[0]) {
      return null;
    }

    return result.rows[0];
  }
  async insertSkillByUser(id, inputData) {
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
    const row = result.rows[0]
    const skillID = row.id;
    await pool.query(
      "INSERT INTO user_has_skill (skill_id, user_id) VALUES ($1, $2)",
      [skillID, id]
    );
  }

  async deleteSkill(id) {
    await pool.query('DELETE FROM "user_has_skill" WHERE skill_id = $1', [id]);

    const result = await pool.query(
      `DELETE FROM "${this.tableName}" WHERE id = $1`,
      [id]
    );
    return !!result.rowCount;
  }
}
module.exports = Skill;
