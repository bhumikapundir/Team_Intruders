const { spawn }   = require('child_process');
const readline    = require('readline');
const express     = require('express');
const http        = require('http');
const { Server }  = require('socket.io');
const fs          = require('fs');
const path        = require('path');

const app    = express();
const server = http.createServer(app);
const io     = new Server(server);

const logStream = fs.createWriteStream(
    path.join(__dirname, 'ids_log.ndjson'), { flags: 'a' }
);

let stats = {
    total     : 0,
    anomalies : {
        same_ip   : 0,
        oversize  : 0,
        statdev   : 0,
        port_scan : 0,
        syn_flood : 0,
        icmp_flood: 0
    },
    topSources: {}
};

function updateStats(pkt) {
    stats.total++;
    if (pkt.same_ip)    stats.anomalies.same_ip++;
    if (pkt.oversize)   stats.anomalies.oversize++;
    if (pkt.statdev)    stats.anomalies.statdev++;
    if (pkt.port_scan)  stats.anomalies.port_scan++;
    if (pkt.syn_flood)  stats.anomalies.syn_flood++;
    if (pkt.icmp_flood) stats.anomalies.icmp_flood++;

    stats.topSources[pkt.src] = (stats.topSources[pkt.src] || 0) + 1;
    const entries = Object.entries(stats.topSources);
    if (entries.length > 10) {
        entries.sort((a, b) => b[1] - a[1]);
        stats.topSources = Object.fromEntries(entries.slice(0, 10));
    }
}

function launchIDS() {
    const iface = process.env.INTERFACE || 'eth0';
    console.log(`[IDS] Launching on interface: ${iface}`);

    const ids = spawn('./ids', [iface]);

    readline.createInterface({ input: ids.stdout })
        .on('line', line => {
            try {
                const pkt = JSON.parse(line);
                updateStats(pkt);
                logStream.write(JSON.stringify({ ...pkt, logged_at: Date.now() }) + '\n');
                io.emit('packet', pkt);
                io.emit('stats', stats);
            } catch {
                console.warn('[IDS] Bad JSON:', line);
            }
        });

    ids.stderr.on('data', d => process.stderr.write(d));

    ids.on('close', code => {
        console.error(`[IDS] Exited (code ${code}). Restarting in 3s...`);
        setTimeout(launchIDS, 3000);
    });
}

app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/stats', (_req, res) => res.json(stats));

app.get('/api/log', (_req, res) => {
    const file = path.join(__dirname, 'ids_log.ndjson');
    if (!fs.existsSync(file)) return res.json([]);
    const lines = fs.readFileSync(file, 'utf8')
        .trim().split('\n')
        .filter(Boolean)
        .slice(-200)
        .map(l => JSON.parse(l));
    res.json(lines);
});

io.on('connection', socket => {
    console.log('[WS] Browser connected');
    socket.emit('stats', stats);
});

server.listen(3000, () => {
    console.log('Dashboard → http://localhost:3000');
    console.log('Stats API → http://localhost:3000/api/stats');
    launchIDS();
});
