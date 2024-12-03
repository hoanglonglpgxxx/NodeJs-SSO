const express = require("express");
const serverless = require("serverless-http");
const bodyParser = require("body-parser");
const OAuth2Server = require("oauth2-server");

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Define your routes
app.get("/authorize", (req, res) => {
    res.send("Authorization endpoint is not implemented yet.");
});

app.post("/token", async (req, res) => {
    const request = new OAuth2Server.Request(req);
    const response = new OAuth2Server.Response(res);

    try {
        const token = await oauth.token(request, response);
        res.json(token);
    } catch (err) {
        res.status(err.code || 500).json(err);
    }
});

module.exports = serverless(app);
