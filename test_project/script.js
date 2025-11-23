import fs from "fs";
import http from "http";

const API_TOKEN = "js-secret-12345"; // hardcoded secret

function getUser(id) {
  const query = "SELECT * FROM users WHERE id = " + id; // unsafe
  console.log(query);
}

function startServer() {
  http
    .createServer((req, res) => {
      res.write("Server OK");
      res.end();
    })
    .listen(3000);
}

class UserManager {
  constructor() {
    this.users = [];
  }
}

export { getUser, startServer };
