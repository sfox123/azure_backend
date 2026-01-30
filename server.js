import express from "express";
import cors from "cors";
import sql from "mssql";
import bcrypt from "bcrypt";
import path from "path";
import { fileURLToPath } from "url";
import "dotenv/config";

const app = express();
app.use(express.json());

app.use(
    cors({
        origin: true,
        credentials: true,
    })
);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

app.use(express.static(path.join(__dirname, "dist")));


const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,      // myfree-sql-server-123.database.windows.net
  database: process.env.DB_NAME,      // free-sql-db-4488044
  options: { encrypt: true },
  pool: { max: 5, min: 0, idleTimeoutMillis: 30000 },
};

app.get("/api/health", (req, res) => res.json({ ok: true }));

app.post("/api/users", async (req, res) => {
  const { name, email, password } = req.body ?? {};

  if (!name || !email || !password) {
    return res.status(400).json({ message: "name, email and password are required" });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 10);

    const pool = await sql.connect(dbConfig);

    // prevent duplicates (basic)
    const existing = await pool
      .request()
      .input("email", sql.NVarChar(255), email)
      .query("SELECT TOP 1 Id FROM dbo.Users WHERE Email=@email");

    if (existing.recordset.length > 0) {
      return res.status(409).json({ message: "Email already registered" });
    }

    await pool
      .request()
      .input("name", sql.NVarChar(100), name)
      .input("email", sql.NVarChar(255), email)
      .input("passwordHash", sql.NVarChar(255), passwordHash)
      .query(
        "INSERT INTO dbo.Users (Name, Email, PasswordHash) VALUES (@name, @email, @passwordHash)"
      );

    return res.status(201).json({ message: "User created" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: "Server error", detail: err.message });
  }
});

// SPA fallback - must be AFTER API routes
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "dist", "index.html"));
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`API running on http://localhost:${port}`));
