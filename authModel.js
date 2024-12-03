const users = [
    { id: "1", name: "Mits 1", email: "mits1@github.com", password: "201000" },
    { id: "2", name: "Mits 2", email: "mits2@github.com", password: "201000" },
];

const tokens = {};

module.exports = {
    getAccessToken: (token) => {
        return tokens[token] || null;
    },

    getClient: (clientId, clientSecret) => {
        if (clientId === "matrix_client_id" && clientSecret === "matrix_client_secret") {
            return { id: clientId, grants: ["password", "authorization_code"] };
        }
        return null;
    },

    saveToken: (token, client, user) => {
        tokens[token.accessToken] = { ...token, client, user };
        return tokens[token.accessToken];
    },

    getUser: (username, password) => {
        return users.find((u) => u.email === username && u.password === password) || null;
    },
};
