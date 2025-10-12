// socket.js — Socket.IO realtime for MTOS
const { Server } = require("socket.io");
const jwt = require("jsonwebtoken");

/**
 * Initialize Socket.IO on the given HTTP server.
 * Exposes notifyUser(userId, event, payload) to other modules.
 */
function initSocket(server, { apiKey, jwtSecret } = {}) {
  const io = new Server(server, {
    cors: { origin: "*", methods: ["GET","POST"] }
  });

  io.use((socket, next) => {
    try {
      const key =
        socket.handshake.auth?.apiKey ||
        socket.handshake.headers["x-api-key"];
      if (!key || key !== apiKey) return next(new Error("Invalid API key"));

      const token =
        socket.handshake.auth?.token ||
        (socket.handshake.headers?.authorization || "").replace(/^Bearer\s+/i, "");
      if (!token) return next(new Error("Missing token"));

      const user = jwt.verify(token, jwtSecret); // { sub, email }
      socket.user = user;
      next();
    } catch {
      next(new Error("Invalid token"));
    }
  });

  io.on("connection", (socket) => {
    const uid = socket.user?.sub;
    if (uid) socket.join(`user:${uid}`);
  });

  // helper for routes to emit
  function notifyUser(userId, event, payload) {
    io.to(`user:${userId}`).emit(event, payload);
  }

  module.exports.notifyUser = notifyUser;
  console.log("✅ Socket.IO initialized");
}

module.exports = { initSocket, notifyUser: () => {} };
