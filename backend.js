import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import Sequelize from "sequelize";
import jwt from "jsonwebtoken";
import multer from "multer";
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import path from "path";
import fs from "fs";

dotenv.config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const upload = multer({ dest: "uploads/" });

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASS,
  {
    host: "161.35.215.240",
    dialect: "mysql",
  }
);

sequelize
  .authenticate()
  .then(() => {
    console.log("Connection has been established successfully.");
  })
  .catch((error) => {
    console.error("Unable to connect to the database: ", error);
  });

const User = sequelize.define("user", {
  id: {
    type: Sequelize.STRING,
    primaryKey: true,
  },
  password: Sequelize.STRING,
});

const File = sequelize.define("file", {
  id: {
    type: Sequelize.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  name: Sequelize.STRING,
  extension: Sequelize.STRING,
  mimeType: Sequelize.STRING,
  size: Sequelize.INTEGER,
  url: Sequelize.STRING,

  uploadDate: Sequelize.DATE,
});

const RefreshToken = sequelize.define(
  "RefreshToken",
  {
    token: {
      type: Sequelize.STRING(500),
      allowNull: false,
    },
  },
  {
    timestamps: false,
  }
);

User.hasMany(File);
File.belongsTo(User);
RefreshToken.belongsTo(User);

sequelize.sync();

function authenticateToken(req, res, next) {
  const token = req.headers.access_token;

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post("/signup", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = await User.create({
      id: req.body.id,
      password: hashedPassword,
    });

    const accessToken = jwt.sign(
      user.toJSON(),
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "10m" }
    );
    const refreshToken = jwt.sign(
      user.toJSON(),
      process.env.REFRESH_TOKEN_SECRET
    );

    await RefreshToken.create({ token: refreshToken, userId: user.id });

    res.json({ accessToken, refreshToken }).status(200);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/signin", async (req, res) => {
  try {
    const user = await User.findOne({ where: { id: req.body.id } });

    if (user == null) {
      return res.status(400).json({ message: "Cannot find user" });
    }

    if (await bcrypt.compare(req.body.password, user.password)) {
      const accessToken = jwt.sign(
        user.toJSON(),
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "10m" }
      );

      const actualRefreshToken = await RefreshToken.findOne({
        where: { userId: user.id },
      });

      if (actualRefreshToken == null) {
        const refreshToken = jwt.sign(
          user.toJSON(),
          process.env.REFRESH_TOKEN_SECRET
        );
        await RefreshToken.create({ token: refreshToken, userId: user.id });
        res.json({ accessToken, refreshToken });
      } else {
        res.json({ accessToken });
      }
    } else {
      res.status(403).json({ message: "Incorrect password" });
    }
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/signin/new_token", (req, res) => {
  const refreshToken = req.body.refresh_token;
  if (refreshToken == null) {
    return res.sendStatus(401);
  }

  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }

    const accessToken = jwt.sign(
      { id: user.id },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "10m" }
    );
    res.json({ accessToken });
  });
});

app.post(
  "/file/upload",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    try {
      const file = req.file;

      const filePath = path.join(path.dirname(import.meta.url), file.path);

      const fileData = {
        name: file.originalname,
        extension: path.extname(file.originalname),
        mimeType: file.mimetype,
        size: file.size,
        uploadDate: new Date(),
        url: filePath,
        userId: req.user.id,
      };

      const createdFile = await File.create(fileData);

      res.json({ file: createdFile });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  }
);

app.get("/file/list", authenticateToken, async (req, res) => {
  try {
    const pageSize = +req.query.list_size || 10;

    const page = req.query.page || 1;

    const files = await File.findAndCountAll({
      where: { userId: req.user.id },
      limit: pageSize,
      offset: (page - 1) * pageSize,
    });

    res.json({ files: files.rows, total: files.count });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/file/delete/:id", authenticateToken, async (req, res) => {
  try {
    const file = await File.findOne({
      where: { id: req.params.id, userId: req.user.id },
    });

    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }
    const newUrl = file.url.split(":")[1];
    fs.unlink(newUrl, (err) => {
      if (err) {
        res.status(500).json({ message: "Failed to delete file" });
      } else {
        file.destroy();
        res.json({ message: "File deleted" });
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/file/:id", authenticateToken, async (req, res) => {
  try {
    const file = await File.findOne({
      where: { id: req.params.id, userId: req.user.id },
    });

    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    res.json({ file });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/file/download/:id", authenticateToken, async (req, res) => {
  try {
    const file = await File.findOne({
      where: { id: req.params.id, userId: req.user.id },
    });

    if (!file) {
      return res.status(404).json({ message: "File not found" });
    }

    res.json(file.url);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.put(
  "/file/update/:id",
  authenticateToken,
  upload.single("file"),
  async (req, res) => {
    try {
      const file = await File.findOne({
        where: { id: req.params.id, userId: req.user.id },
      });

      if (!file) {
        return res.status(404).json({ message: "File not found" });
      }

      const newUrl = file.url.split(":")[1];
      fs.unlink(newUrl, (err) => {
        if (err) {
          res.status(500).json({ message: "Failed to delete file" });
        } else {
          file.destroy();
        }
      });

      const updatedFileData = {
        name: req.file.originalname,
        extension: path.extname(req.file.originalname),
        mimeType: req.file.mimetype,
        size: req.file.size,
        uploadDate: new Date(),
        url: path.join(path.dirname(import.meta.url), req.file.path),
      };

      await file.update(updatedFileData);

      res.json({ message: "File updated", file });
    } catch (err) {
      res.status(500).json({ message: err.message });
    }
  }
);

app.get("/info", authenticateToken, async (req, res) => {
  try {
    res.json({ id: req.user.id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
app.get("/logout", async (req, res) => {
  try {
    const token = req.headers.refresh_token;
    const refreshToken = await RefreshToken.findOne({
      where: { token: token },
    });

    if (refreshToken) {
      await refreshToken.destroy();
      return res.json({ message: "Logged out successfully" });
    }

    res.status(404).json({ message: "Not Found" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.listen(5001, () => {
  console.log("Server is running on port 5001");
});
