const Core = require("./coreModel");

const pool = require("../services/dbClient");

class Feed extends Core {
  static tableName = "feed";
  constructor() {
    super();
    this.tableName = "feed";
  }
  async findFeedByUser(id) {
    const preparedQuery = {
      text: `SELECT "feed".* FROM "feed" JOIN "feed_has_user" 
           ON feed.id = feed_has_user.feed_id  
           WHERE feed_has_user.user_id = $1
        `,
      values: [id],
    };

    const result = await pool.query(preparedQuery);

    if (!result.rows[0]) {
      return null;
    }

    return result.rows;
  }
  
  async insertFeedByUser(id, inputData) {
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
    const feedID = row.id;
    console.log(feedID);
    await pool.query(
      "INSERT INTO feed_has_user (feed_id, user_id) VALUES ($1, $2)",
      [feedID, id]
    );
    return row;
  }

  async deleteFeed(id) {
    await pool.query('DELETE FROM "feed_has_user" WHERE feed_id = $1', [id]);

    const result = await pool.query(
      `DELETE FROM "${this.tableName}" WHERE id = $1`,
      [id]
    );
    return !!result.rowCount;
  }
}
module.exports = Feed;
