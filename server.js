const express = require("express");
const bodyParser = require("body-parser");
const OAuth2Server = require("oauth2-server");

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Initialize OAuth2 server
const oauth = new OAuth2Server({
    model: require("./authModel"), // Import the OAuth2 model
    accessTokenLifetime: 3600,
    allowBearerTokensInQueryString: true,
});

// Middleware to handle OAuth requests
const request = OAuth2Server.Request;
const response = OAuth2Server.Response;

// Authorization endpoint
app.get("/authorize", (req, res) => {
    // You can implement a custom user authentication flow here
    res.send("Authorization endpoint is not implemented yet.");
});

// Token endpoint
app.post("/token", async (req, res) => {
    const oauthRequest = new request(req);
    const oauthResponse = new response(res);

    try {
        const token = await oauth.token(oauthRequest, oauthResponse);
        res.json(token);
    } catch (err) {
        res.status(err.code || 500).json(err);
    }
});

// Userinfo endpoint
app.get("/userinfo", async (req, res) => {
    const oauthRequest = new request(req);
    const oauthResponse = new response(res);

    try {
        const token = await oauth.authenticate(oauthRequest, oauthResponse);
        // Return user information
        res.json({
            sub: token.user.id,
            name: token.user.name,
            email: token.user.email,
        });
    } catch (err) {
        res.status(err.code || 500).json(err);
    }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`OAuth2 provider is running on http://localhost:${PORT}`);
});
