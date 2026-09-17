const express = require("express");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, "data.json");

app.use(express.json({ limit: "1mb" }));

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const data = { users: [], videos: [] };
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
    return data;
  }

  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {
    return { users: [], videos: [] };
  }
}

function saveData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

let db = loadData();

const sessions = new Map();
const SESSION_TIME = 12 * 60 * 60 * 1000;

function createAdmin() {
  const username = process.env.ADMIN_USERNAME;
  const password = process.env.ADMIN_PASSWORD;

  if (!username || !password) {
    console.log("ADMIN_USERNAME / ADMIN_PASSWORD not configured.");
    return;
  }

  const exists = db.users.find(
    user => user.username.toLowerCase() === username.toLowerCase()
  );

  if (!exists) {
    db.users.push({
      id: crypto.randomUUID(),
      username,
      passwordHash: bcrypt.hashSync(password, 12),
      role: "admin",
      createdAt: new Date().toISOString()
    });

    saveData(db);
    console.log("Admin account created.");
  }
}

createAdmin();

function auth(req, res, next) {
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

  const user = db.users.find(
    item => item.id === session.userId
  );

  if (!user) {
    sessions.delete(token);

    return res.status(401).json({
      error: "User not found"
    });
  }

  req.user = user;
  req.token = token;

  next();
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

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "AXOM Backend"
  });
});


/* LOGIN */

app.post("/api/auth/login", async (req, res) => {
  const username = String(req.body?.username || "").trim();
  const password = String(req.body?.password || "");

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required"
    });
  }

  const user = db.users.find(
    item =>
      item.username.toLowerCase() === username.toLowerCase()
  );

  if (!user) {
    return res.status(401).json({
      error: "Invalid username or password"
    });
  }

  const valid = await bcrypt.compare(
    password,
    user.passwordHash
  );

  if (!valid) {
    return res.status(401).json({
      error: "Invalid username or password"
    });
  }

  const token = crypto.randomBytes(32).toString("hex");

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
});


/* LOGOUT */

app.post("/api/auth/logout", auth, (req, res) => {
  sessions.delete(req.token);

  res.json({
    ok: true
  });
});


/* VIDEOS */

app.get("/api/videos", auth, (req, res) => {
  const videos = db.videos.map(video => ({
    id: video.id,
    title: video.title
  }));

  res.json(videos);
});


/* ADMIN USERS */

app.get(
  "/api/admin/users",
  auth,
  adminOnly,
  (req, res) => {

    const users = db.users.map(user => ({
      id: user.id,
      username: user.username,
      role: user.role,
      createdAt: user.createdAt
    }));

    res.json(users);
  }
);


/* ADD VIDEO */

app.post(
  "/api/admin/videos",
  auth,
  adminOnly,
  (req, res) => {

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

    let parsedURL;

    try {
      parsedURL = new URL(url);
    } catch {
      return res.status(400).json({
        error: "Invalid URL"
      });
    }

    if (
      parsedURL.protocol !== "https:" &&
      parsedURL.protocol !== "http:"
    ) {
      return res.status(400).json({
        error: "Only HTTP/HTTPS URLs are allowed"
      });
    }

    const video = {
      id: crypto.randomUUID(),
      title,
      url,
      createdAt: new Date().toISOString()
    };

    db.videos.push(video);

    saveData(db);

    res.status(201).json({
      id: video.id,
      title: video.title
    });
  }
);


/* DELETE VIDEO */

app.delete(
  "/api/admin/videos/:id",
  auth,
  adminOnly,
  (req, res) => {

    const oldLength = db.videos.length;

    db.videos = db.videos.filter(
      video => video.id !== req.params.id
    );

    if (db.videos.length === oldLength) {
      return res.status(404).json({
        error: "Video not found"
      });
    }

    saveData(db);

    res.json({
      ok: true
    });
  }
);


/* VIDEO STREAM */

app.get(
  "/api/videos/:id/stream",
  auth,
  async (req, res) => {

    const video = db.videos.find(
      item => item.id === req.params.id
    );

    if (!video) {
      return res.status(404).json({
        error: "Video not found"
      });
    }

    try {
      const headers = {};

      if (req.headers.range) {
        headers.Range = req.headers.range;
      }

      const response = await fetch(
        video.url,
        {
          headers,
          redirect: "follow"
        }
      );

      if (!response.ok && response.status !== 206) {
        return res.status(502).json({
          error: "Unable to load video source"
        });
      }

      res.status(response.status);

      const contentType =
        response.headers.get("content-type");

      const contentLength =
        response.headers.get("content-length");

      const contentRange =
        response.headers.get("content-range");

      const acceptRanges =
        response.headers.get("accept-ranges");

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

      if (acceptRanges) {
        res.setHeader(
          "Accept-Ranges",
          acceptRanges
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
        "Video error:",
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


app.listen(PORT, () => {
  console.log(
    `AXOM backend running on port ${PORT}`
  );
});