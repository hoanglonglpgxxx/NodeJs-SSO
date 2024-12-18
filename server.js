const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const fs = require("fs");
const jose = require("node-jose");

const app = express();
const PORT = process.env.PORT || 3000;

const users = [
    { username: "mits1", password: "pass1", id: "1", name: "Lê Hoàng A" },
    { username: "mits2", password: "pass2", id: "2", name: "Lê Hoàng B" },
];

const CLIENT_ID = "TOKANNANANANA";
const CLIENT_SECRET = "TOKENANANANA";
const REDIRECT_URI = "https://matrix.mitsngeither.me/_synapse/client/oidc/callback";
const JWT_SECRET = "c2509ffc604e84ccd997735ba8edafd23372424cfad27427d8741ec0840ecdd8";

const authorizationCodes = new Map();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Login Endpoint
app.get("/login", (req, res) => {
    const { client_id, redirect_uri, state, nonce } = req.query;

    if (client_id !== CLIENT_ID || redirect_uri !== REDIRECT_URI) {
        return res.status(400).send("Invalid client_id or redirect_uri");
    }

    console.log('Login route nounce param', nonce);


    res.send(`
        <form method="POST" action="/authorize">
            <input type="hidden" name="state" value="${state}" />
            <input type="hidden" name="redirect_uri" value="${redirect_uri}" />
            <input type="hidden" name="client_id" value="${client_id}" />
            <input type="hidden" name="nonce" value="${nonce}" />
            <input type="text" name="username" placeholder="Username" required />
            <input type="password" name="password" placeholder="Password" required />
            <button type="submit">Login</button>
        </form>
    `);
});

// Authorize Endpoint
app.post("/authorize", (req, res) => {
    const { username, password, client_id, redirect_uri, state, nonce } = req.body;

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
    authorizationCodes.set(authCode, { user, client_id, redirect_uri, nonce });

    // Redirect back to the redirect_uri with the code and state
    res.redirect(`${redirect_uri}?code=${authCode}&state=${state}`);
    console.log("Redirecting to:", `${redirect_uri}?code=${authCode}&state=${state}`, `nonce: ${nonce}`);
});

const privateKey = fs.readFileSync("keys/private_key.pem", "utf8");

// Token Endpoint
app.post("/token", (req, res) => {
    let clientId = req.body.client_id;
    let clientSecret = req.body.client_secret;

    // If not in body, check Authorization header
    if (!clientId || !clientSecret) {
        const authHeader = req.headers.authorization;
        if (authHeader && authHeader.startsWith("Basic ")) {
            const base64Credentials = authHeader.split(" ")[1];
            const credentials = Buffer.from(base64Credentials, "base64").toString("ascii");
            [clientId, clientSecret] = credentials.split(":");
        }
    }

    console.log("Parsed client_id:", clientId);
    console.log("Parsed client_secret:", clientSecret);

    const { grant_type, code, redirect_uri } = req.body;
    console.log('token route', grant_type, code, redirect_uri, clientId, clientSecret);

    if (
        clientId !== CLIENT_ID ||
        clientSecret !== CLIENT_SECRET ||
        redirect_uri !== REDIRECT_URI ||
        grant_type !== "authorization_code"
    ) {
        return res.status(400).send("Invalid client credentials, redirect_uri, or grant_type");
    }

    const authCode = authorizationCodes.get(code);
    if (!authCode) {
        return res.status(400).send("Invalid or expired authorization code");
    }

    // Generate ID Token
    const idToken = jwt.sign(
        {
            iss: "https://matrix-mits-h5h3evd7a6g3a0gb.eastasia-01.azurewebsites.net",
            sub: authCode.user.username,
            aud: CLIENT_ID,
            exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour expiration
            iat: Math.floor(Date.now() / 1000), // Issued at
            nonce: authCode.nonce, // Pass through nonce if available
        },
        privateKey,
        { algorithm: "RS256" }
    );

    // Generate Access Token
    const accessToken = jwt.sign({ userId: authCode.user.id }, JWT_SECRET, { expiresIn: "1h" });

    res.json({
        access_token: accessToken,
        id_token: idToken,
        token_type: "Bearer",
        expires_in: 3600,
    });

    console.log("Received /token request");
    console.log("Client ID:", clientId);
    console.log("Client Secret:", clientSecret);
    console.log("Grant Type:", grant_type);
    console.log("Code:", code);
    console.log("Redirect URI:", redirect_uri);

    console.log("Retrieved authorization code:", authCode);

    authorizationCodes.delete(code);
});


// Userinfo Endpoint
app.get("/userinfo", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        console.error("Missing or invalid authorization header");
        return res.status(401).send("Missing or invalid authorization header");
    }

    const token = authHeader.split(" ")[1];

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        console.log('Token payload:', payload);

        const user = users.find((u) => u.id === payload.userId);
        console.log('User found:', user);

        if (!user) {
            console.error("User not found");
            return res.status(404).send("User not found");
        }

        const userInfo = {
            sub: user.id,
            username: user.username,
            name: user.name,
        };

        res.json(userInfo);
    } catch (err) {
        console.error("Token verification error:", err);
        res.status(401).send("Invalid token");
    }
});

// Load the public key and create JWK
const publicKey = fs.readFileSync("keys/public_key.pem", "utf8");

jose.JWK.asKey(publicKey, "pem")
    .then((key) => {
        const jwks = {
            keys: [
                {
                    alg: key.alg || "RS256",
                    kty: key.kty || "RSA",
                    use: "sig",
                    kid: key.kid || crypto.randomBytes(8).toString("hex"),
                    n: key.n || key.toJSON().n,
                    e: key.e || key.toJSON().e,
                },
            ],
        };

        app.get("/.well-known/jwks.json", (req, res) => {
            res.json(jwks);
        });

        app.listen(PORT, () => {
            console.log(`OAuth2 provider is running on http://localhost:${PORT}`);
        });
    })
    .catch((err) => {
        console.error("Error creating JWKS/loading public key testtesttest:", err);
    });


