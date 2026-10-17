# CodeAlpha_VideoConference
Task 4 – Real-Time Communication App. Stack: WebRTC, Socket.io, Express.js, SQLite.
Features: multi-user video calling (mesh), screen sharing, peer-to-peer file sharing, shared whiteboard, user authentication, encryption (WebRTC DTLS-SRTP for media and data channels; bcrypt + JWT for auth).
Run: `npm install && npm start` → http://localhost:3003 (open in 2+ tabs/devices, same room name).
Camera access needs localhost or HTTPS. For HTTPS set `SSL_KEY` and `SSL_CERT` to your key/cert file paths. For calls across different networks, add a TURN server to the ICE config in `public/index.html`.
