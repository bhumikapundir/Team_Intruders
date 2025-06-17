const { spawn } = require('child_process');
const readline  = require('readline');
const express   = require('express');
const http      = require('http');
const { Server } = require('socket.io');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server);

// Serve frontend files from ./public
app.use(express.static('public'));

// Launch the C++ IDS binary
const ids = spawn('./ids');          // assumes ids is in the same folder

// Read each JSON line from IDS stdout
readline.createInterface({ input: ids.stdout })
  .on('line', line => {
    try {
      const pkt = JSON.parse(line);
      io.emit('packet', pkt);        // broadcast to all connected browsers
    } catch {
      console.warn('Bad JSON:', line);
    }
  });

// Forward IDS stderr to console
ids.stderr.on('data', data => process.stderr.write(data));

// WebSocket connection log
io.on('connection', () => console.log('🔗 Browser connected'));

// Start HTTP server
server.listen(3000, () => console.log('🌍 Open http://localhost:3000'));