import { Sequelize } from "sequelize";

export class Database {
  private static instance: Database;
  public sequelize: Sequelize;
  private constructor() {
    this.sequelize = new Sequelize("bms", "sourav", "sourav", {
      host: "localhost",
      port: 3306,
      dialect: "mysql",
    });
  }

  public static getInstance(): Database {
    if (!Database.instance) {
      Database.instance = new Database();
    }
    return Database.instance;
  }

  public async dbConnect() {
    try {
      await this.sequelize.authenticate();
      console.log("DB Connection has been established successfully.");
      (async () => {
        await this.sequelize
          .sync({ force: false })
          .then(() => console.log("Database synchronized successfully."))
          .catch((error) =>
            console.error("Error synchronizing the database:", error)
          );
      })();
    } catch (error) {
      console.error("Unable to connect to the database:", error);
    }
  }
}
