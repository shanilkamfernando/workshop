import pkg from "pg";
import dotenv from "dotenv";
dotenv.config();

const { Pool } = pkg;

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_NAME,
  password: process.env.DB_PASS,
  port: process.env.DB_PORT, // 5432
});

pool.connect()
.then(() => console.log("connected to postgreSQL"))
.catch(err => console.log("DB connection error", err));
export default pool;
