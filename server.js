const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;

const users = [
    { username: "mits1", password: "pass1", id: "1" },
    { username: "mits2", password: "pass2", id: "2" },
];

const CLIENT_ID = "TOKANNANANANA";
const CLIENT_SECRET = "TOKENANANANA";
const REDIRECT_URI = "https://matrix.mitsngeither.me/_synapse/oidc/callback";
const JWT_SECRET = "supersecretkey";

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get("/login", (req, res) => {
    const { client_id, redirect_uri, state } = req.query;

    if (client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
        return res.status(400).send("Invalid client_id or redirect_uri");
    }

    res.send(`
    <form method="POST" action="/authorize">
      <input type="hidden" name="state" value="${state}" />
      <input type="text" name="username" placeholder="Username" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Login</button>
    </form>
  `);
});

app.post("/authorize", (req, res) => {
    const { username, password, state } = req.body;

    const user = users.find((u) => u.username === username && u.password === password);

    if (!user) {
        return res.status(401).send("Invalid credentials");
    }

    const code = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "5m" });

    res.redirect(`${REDIRECT_URI}?code=${code}&state=${state}`);
});

app.post("/token", (req, res) => {
    const { code, client_id, client_secret } = req.body;

    if (client_id !== CLIENT_ID || client_secret !== CLIENT_SECRET) {
        return res.status(400).send("Invalid client_id or client_secret");
    }

    try {
        const payload = jwt.verify(code, JWT_SECRET);
        const token = jwt.sign({ userId: payload.userId }, JWT_SECRET, { expiresIn: "1h" });

        res.json({
            access_token: token,
            token_type: "Bearer",
            expires_in: 3600,
        });
    } catch (err) {
        res.status(400).send("Invalid code");
    }
});

app.get("/userinfo", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).send("Missing or invalid authorization header");
    }

    const token = authHeader.split(" ")[1];

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const user = users.find((u) => u.id === payload.userId);

        if (!user) {
            return res.status(404).send("User not found");
        }

        res.json({
            sub: user.id,
            name: user.username,
        });
    } catch (err) {
        res.status(400).send("Invalid token");
    }
});

app.listen(PORT, () => {
    console.log(`OAuth2 provider is running on http://localhost:${PORT}`);
});
