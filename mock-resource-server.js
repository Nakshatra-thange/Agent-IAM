import express from "express";
import dotenv from "dotenv";
import { requireScope } from "./auth-middleware.js";

dotenv.config();
const app = express();
app.use(express.json());

// Read-only endpoint — needs github:repo:read
app.get("/github/repos/:repo", requireScope("github", "github:repo:read"), (req, res) => {
  res.json({
    repo: req.params.repo,
    accessed_by: req.agent.name,
    files: ["server.js", "package.json", "README.md"],
  });
});

// Write endpoint — needs github:pr:write (a DIFFERENT scope, deliberately)
app.post("/github/repos/:repo/pulls", requireScope("github", "github:pr:write"), (req, res) => {
  res.status(201).json({
    message: `PR opened on ${req.params.repo} by ${req.agent.name}`,
    pr_number: Math.floor(Math.random() * 1000),
    title: req.body.title || "Automated change",
  });
});

app.listen(5000, () => {
  console.log("Mock GitHub resource server running on http://localhost:5000");
});