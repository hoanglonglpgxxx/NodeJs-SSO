const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

const users = [
    { username: "mits1", password: "pass1", id: "1" },
    { username: "mits2", password: "pass2", id: "2" },
];

const CLIENT_ID = "TOKANNANANANA";
const CLIENT_SECRET = "TOKENANANANA";
const REDIRECT_URI = "https://matrix.mitsngeither.me/_synapse/client/oidc/callback";
const JWT_SECRET = "your_jwt_secret"; // Replace with your actual JWT secret

// Configure body-parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

app.get("/login", (req, res) => {
    const client_id = req.query.client_id?.trim();
    const redirect_uri = req.query.redirect_uri?.trim();
    const state = req.query.state;

    console.log("Received client_id:", client_id);
    console.log("Received redirect_uri:", redirect_uri);

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

    // Generate a JWT token
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

    // Redirect to the redirect_uri with the token
    res.redirect(`${REDIRECT_URI}?token=${token}&state=${state}`);
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