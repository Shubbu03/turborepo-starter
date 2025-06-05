import express, { Request, Response } from "express";
import cors from "cors";
import { prisma } from "@repo/prisma";
import { hashPassword, comparePassword } from "@repo/auth/bcrypt";
import { signToken } from "@repo/auth/jwt/signToken";

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
  res.send("Express App");
});

app.post("/signup", async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({
        error: "Username and password are required",
      });
      return;
    }

    if (password.length < 6) {
      res.status(400).json({
        error: "Password must be at least 6 characters long",
      });
      return;
    }

    const existingUser = await prisma.user.findUnique({
      where: { username },
    });

    if (existingUser) {
      res.status(409).json({
        error: "Username already exists",
      });
      return;
    }

    const hashedPassword = await hashPassword(password, 10);

    const newUser = await prisma.user.create({
      data: {
        username,
        password: hashedPassword,
      },
    });

    res.status(201).json({
      message: "User created successfully",
      user: {
        id: newUser.id,
        username: newUser.username,
      },
    });
  } catch (error) {
    console.error("Signup error:", error);
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.post("/login", async (req: Request, res: Response): Promise<void> => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      res.status(400).json({
        error: "Username and password are required",
      });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { username },
    });

    if (!user) {
      res.status(401).json({
        error: "Invalid credentials",
      });
      return;
    }

    const isValidPassword = await comparePassword(password, user.password);

    if (!isValidPassword) {
      res.status(401).json({
        error: "Invalid credentials",
      });
      return;
    }

    const token = signToken(username, "your-jwt-secret");

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        id: user.id,
        username: user.username,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      error: "Internal server error",
    });
  }
});

app.listen(3000, () => {
  console.log("Express Server started on port 3000");
});
