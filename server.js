const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" }));

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

const sessions = new Map();
const SESSION_TIME = 12 * 60 * 60 * 1000;


/* DATABASE */

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS videos (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      title TEXT NOT NULL,
      url TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  console.log("Database ready.");
}


/* ADMIN */

async function createAdmin() {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  if (!username || !password) {
    console.log(
      "ADMIN_USERNAME or ADMIN_PASSWORD is missing."
    );
    return;
  }

  const result = await pool.query(
    "SELECT id FROM users WHERE LOWER(username)=LOWER($1)",
    [username]
  );

  if (result.rows.length === 0) {
    const hash = await bcrypt.hash(password, 12);

    await pool.query(
      `INSERT INTO users
       (username, password_hash, role)
       VALUES ($1, $2, 'admin')`,
      [username, hash]
    );

    console.log("Admin account created.");
  }
}


/* AUTH */

async function auth(req, res, next) {
  try {
    const header = req.headers.authorization || "";

    if (!header.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const token = header.substring(7);
    const session = sessions.get(token);

    if (!session || session.expiresAt < Date.now()) {
      sessions.delete(token);

      return res.status(401).json({
        error: "Session expired"
      });
    }

    const result = await pool.query(
      `SELECT id, username, role, created_at
       FROM users
       WHERE id=$1`,
      [session.userId]
    );

    if (result.rows.length === 0) {
      sessions.delete(token);

      return res.status(401).json({
        error: "User not found"
      });
    }

    req.user = result.rows[0];
    req.token = token;

    next();

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Authentication error"
    });
  }
}


function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      error: "Admin access required"
    });
  }

  next();
}


/* HEALTH */

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.json({
      ok: true,
      database: "connected",
      service: "AXOM Backend"
    });

  } catch {
    res.status(500).json({
      ok: false,
      database: "error"
    });
  }
});


/* LOGIN */

app.post("/api/auth/login", async (req, res) => {
  try {
    const username = String(
      req.body?.username || ""
    ).trim();

    const password = String(
      req.body?.password || ""
    );

    if (!username || !password) {
      return res.status(400).json({
        error: "Username and password are required"
      });
    }

    const result = await pool.query(
      `SELECT id, username, password_hash, role
       FROM users
       WHERE LOWER(username)=LOWER($1)`,
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    const user = result.rows[0];

    const valid = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid username or password"
      });
    }

    const token = crypto
      .randomBytes(32)
      .toString("hex");

    sessions.set(token, {
      userId: user.id,
      expiresAt: Date.now() + SESSION_TIME
    });

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Login failed"
    });
  }
});


/* LOGOUT */

app.post("/api/auth/logout", auth, (req, res) => {
  sessions.delete(req.token);

  res.json({
    ok: true
  });
});


/* VIDEOS */

app.get("/api/videos", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, title
       FROM videos
       ORDER BY created_at DESC`
    );

    res.json(result.rows);

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Unable to load videos"
    });
  }
});


/* ADMIN USERS */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  async (req, res) => {

    try {
      const result = await pool.query(
        `SELECT id, username, role, created_at
         FROM users
         ORDER BY created_at DESC`
      );

      res.json(
        result.rows.map(user => ({
          id: user.id,
          username: user.username,
          role: user.role,
          createdAt: user.created_at
        }))
      );

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to load users"
      });
    }
  }
);


/* ADD VIDEO */

app.post(
  "/api/admin/videos",
  auth,
  adminOnly,
  async (req, res) => {

    try {
      const title = String(
        req.body?.title || ""
      ).trim();

      const url = String(
        req.body?.url || ""
      ).trim();

      if (!title || !url) {
        return res.status(400).json({
          error: "Title and URL are required"
        });
      }

      let parsed;

      try {
        parsed = new URL(url);
      } catch {
        return res.status(400).json({
          error: "Invalid URL"
        });
      }

      if (
        parsed.protocol !== "https:" &&
        parsed.protocol !== "http:"
      ) {
        return res.status(400).json({
          error: "Only HTTP/HTTPS URLs are allowed"
        });
      }

      const result = await pool.query(
        `INSERT INTO videos
         (title, url)
         VALUES ($1, $2)
         RETURNING id, title`,
        [title, url]
      );

      res.status(201).json(
        result.rows[0]
      );

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to add video"
      });
    }
  }
);


/* DELETE VIDEO */

app.delete(
  "/api/admin/videos/:id",
  auth,
  adminOnly,
  async (req, res) => {

    try {
      const result = await pool.query(
        `DELETE FROM videos
         WHERE id=$1
         RETURNING id`,
        [req.params.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Video not found"
        });
      }

      res.json({
        ok: true
      });

    } catch (error) {
      console.error(error);

      res.status(500).json({
        error: "Unable to delete video"
      });
    }
  }
);


/* VIDEO STREAM */

app.get(
  "/api/videos/:id/stream",
  auth,
  async (req, res) => {

    try {
      const result = await pool.query(
        `SELECT url
         FROM videos
         WHERE id=$1`,
        [req.params.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "Video not found"
        });
      }

      const url = result.rows[0].url;

      const headers = {};

      if (req.headers.range) {
        headers.Range = req.headers.range;
      }

      const response = await fetch(url, {
        headers,
        redirect: "follow"
      });

      if (!response.ok && response.status !== 206) {
        return res.status(502).json({
          error: "Video source unavailable"
        });
      }

      res.status(response.status);

      const contentType =
        response.headers.get("content-type");

      const contentLength =
        response.headers.get("content-length");

      const contentRange =
        response.headers.get("content-range");

      if (contentType) {
        res.setHeader(
          "Content-Type",
          contentType
        );
      }

      if (contentLength) {
        res.setHeader(
          "Content-Length",
          contentLength
        );
      }

      if (contentRange) {
        res.setHeader(
          "Content-Range",
          contentRange
        );
      }

      if (!response.body) {
        return res.end();
      }

      for await (const chunk of response.body) {
        if (!res.write(chunk)) {
          await new Promise(resolve =>
            res.once("drain", resolve)
          );
        }
      }

      res.end();

    } catch (error) {
      console.error(
        "Stream error:",
        error.message
      );

      if (!res.headersSent) {
        res.status(502).json({
          error: "Video source unavailable"
        });
      }
    }
  }
);


/* START */

async function start() {
  try {
    await setupDatabase();
    await createAdmin();

    app.listen(PORT, () => {
      console.log(
        `AXOM backend running on port ${PORT}`
      );
    });

  } catch (error) {
    console.error(
      "Startup failed:",
      error
    );

    process.exit(1);
  }
}

start();
