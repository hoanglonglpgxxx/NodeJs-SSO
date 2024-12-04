const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const users = [
    { username: "mits1", password: "pass1", id: "1" },
    { username: "mits2", password: "pass2", id: "2" },
];

const CLIENT_ID = "TOKANNANANANA";
const CLIENT_SECRET = "TOKENANANANA";
const REDIRECT_URI = "https://matrix.mitsngeither.me/_synapse/client/oidc/callback";
const JWT_SECRET = "your_jwt_secret"; // Replace with a strong secret

// Temporary in-memory storage for authorization codes
const authorizationCodes = new Map();

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Login Endpoint
app.get("/login", (req, res) => {
    const { client_id, redirect_uri, state } = req.query;

    if (client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
        return res.status(400).send("Invalid client_id or redirect_uri");
    }

    res.send(`
        <form method="POST" action="/authorize">
            <input type="hidden" name="state" value="${state}" />
            <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
            <input type="hidden" name="client_id" value="${client_id}" />
            <input type="text" name="username" placeholder="Username" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Login</button>
        </form>
    `);
});

// Authorize Endpoint
app.post("/authorize", (req, res) => {
    const { username, password, client_id, redirect_uri, state } = req.body;

    if (client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
        return res.status(400).send("Invalid client_id or redirect_uri");
    }

    const user = users.find((u) => u.username === username && u.password === password);

    if (!user) {
        return res.status(401).send("Invalid credentials");
    }

    // Generate an authorization code
    const authCode = crypto.randomBytes(20).toString("hex");

    // Store the authorization code with user and client details
    authorizationCodes.set(authCode, { user, client_id, redirect_uri });

    // Redirect back to the redirect_uri with the code and state
    res.redirect(`${redirect_uri}?code=${authCode}&state=${state}`);
});

// Token Endpoint
app.post("/token", (req, res) => {
    const { grant_type, code, redirect_uri, client_id, client_secret } = req.body;
    console.log(grant_type, code, redirect_uri, client_id, client_secret);

    if (
        client_id !== CLIENT_ID ||
        client_secret !== CLIENT_SECRET ||
        redirect_uri !== REDIRECT_URI ||
        grant_type !== "authorization_code"
    ) {
        return res.status(400).send("Invalid client credentials, redirect_uri, or grant_type");
    }

    const authCode = authCodes.find((c) => c.code === code);
    if (!authCode) {
        return res.status(400).send("Invalid or expired authorization code");
    }

    // Generate and return the access token
    const token = jwt.sign({ userId: authCode.userId }, JWT_SECRET, { expiresIn: "1h" });

    res.json({
        access_token: token,
        token_type: "Bearer",
        expires_in: 3600,
    });
});

// Userinfo Endpoint
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
        res.status(401).send("Invalid token");
    }
});

const jwks = {
    keys: [
        {
            alg: "RS256",
            kty: "RSA",
            use: "sig",
            kid: "your-key-id",
            n: "base64url-encoded-public-key",
            e: "AQAB",
        },
    ],
};

app.get("/.well-known/jwks.json", (req, res) => {
    res.json(jwks);
});


// Start the Server
app.listen(PORT, () => {
    console.log(`OAuth2 provider is running on http://localhost:${PORT}`);
});
