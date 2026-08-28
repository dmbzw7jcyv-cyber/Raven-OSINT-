#!/usr/bin/env node
// Raven.js — Advanced OSINT Framework (Node.js Version)
// Templar Studios — GPL v3.0

const crypto = require('crypto');
const readline = require('readline');
const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// ─── HTTP CLIENT ───
function httpRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;
        
        const req = lib.get(url, {
            headers: {
                'User-Agent': USER_AGENT,
                'Accept': 'text/html,application/xhtml+xml',
                ...options.headers
            },
            timeout: options.timeout || 10000
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
        });
        
        req.on('error', reject);
        req.on('timeout', () => req.destroy(new Error('Timeout')));
    });
}

// ─── HASH FUNCTIONS ───
function sha1(data) { return crypto.createHash('sha1').update(data).digest('hex').toUpperCase(); }
function sha256(data) { return crypto.createHash('sha256').update(data).digest('hex'); }
function sha512(data) { return crypto.createHash('sha512').update(data).digest('hex'); }
function md5(data) { return crypto.createHash('md5').update(data).digest('hex'); }

// ─── USERNAME SEARCH ───
async function searchUsername(username) {
    const platforms = {
        'GitHub': `https://github.com/${username}`,
        'Twitter/X': `https://twitter.com/${username}`,
        'Instagram': `https://instagram.com/${username}`,
        'Reddit': `https://reddit.com/user/${username}`,
        'TikTok': `https://tiktok.com/@${username}`,
        'YouTube': `https://youtube.com/@${username}`,
        'Twitch': `https://twitch.tv/${username}`,
        'Pinterest': `https://pinterest.com/${username}`,
        'Tumblr': `https://${username}.tumblr.com`,
        'Flickr': `https://flickr.com/people/${username}`,
        'SoundCloud': `https://soundcloud.com/${username}`,
        'DeviantArt': `https://deviantart.com/${username}`,
        'Mastodon': `https://mastodon.social/@${username}`,
        'Steam': `https://steamcommunity.com/id/${username}`,
        'Roblox': `https://roblox.com/user.aspx?username=${username}`,
        'LinkedIn': `https://linkedin.com/in/${username}`,
        'Medium': `https://medium.com/@${username}`,
        'Dev.to': `https://dev.to/${username}`,
        'GitLab': `https://gitlab.com/${username}`,
        'Pastebin': `https://pastebin.com/u/${username}`,
        'Keybase': `https://keybase.io/${username}`,
        'Spotify': `https://open.spotify.com/user/${username}`,
        'Imgur': `https://imgur.com/user/${username}`,
        'ProductHunt': `https://www.producthunt.com/@${username}`,
        'HackerNews': `https://news.ycombinator.com/user?id=${username}`,
        'HackerOne': `https://hackerone.com/${username}`,
        'CodePen': `https://codepen.io/${username}`,
        'Replit': `https://replit.com/@${username}`,
        'Kaggle': `https://www.kaggle.com/${username}`,
        'Patreon': `https://www.patreon.com/${username}`
    };
    
    const results = {};
    let found = 0;
    
    const promises = Object.entries(platforms).map(async ([platform, url]) => {
        try {
            const resp = await httpRequest(url, { timeout: 8000 });
            const notFoundMarkers = ['not found', 'does not exist', 'page not found', 'user not found', 'profile not found'];
            const body = resp.body.toLowerCase();
            const exists = resp.status === 200 && !notFoundMarkers.some(m => body.includes(m));
            
            results[platform] = { exists, url, status: resp.status };
            if (exists) found++;
            
            return { platform, exists, url, status: resp.status };
        } catch {
            results[platform] = { exists: false, url, status: 0 };
            return { platform, exists: false, url, status: 0 };
        }
    });
    
    await Promise.all(promises);
    
    return {
        username,
        results,
        total_platforms: Object.keys(platforms).length,
        found_count: found
    };
}

// ─── EMAIL BREACH CHECK ───
async function checkEmailBreach(email) {
    const emailHash = sha1(email.toLowerCase());
    const prefix = emailHash.slice(0, 5);
    const suffix = emailHash.slice(5);
    
    try {
        const resp = await httpRequest(`https://api.pwnedpasswords.com/range/${prefix}`, { timeout: 15000 });
        if (resp.status === 200) {
            const lines = resp.body.split('\n');
            for (const line of lines) {
                const [hashSuffix, count] = line.split(':');
                if (hashSuffix === suffix) {
                    return { breached: true, count: parseInt(count), email };
                }
            }
            return { breached: false, count: 0, email };
        }
    } catch {}
    
    return { breached: false, count: -1, email };
}

// ─── PORT SCANNER ───
async function scanPort(host, port) {
    return new Promise((resolve) => {
        const socket = net.createConnection({ host, port, timeout: 3000 });
        socket.on('connect', () => {
            socket.destroy();
            resolve({ port, open: true });
        });
        socket.on('error', () => resolve({ port, open: false }));
        socket.on('timeout', () => {
            socket.destroy();
            resolve({ port, open: false });
        });
    });
}

async function scanPorts(host, ports = [21,22,23,25,53,80,110,135,139,143,443,445,993,995,3306,3389,5432,5900,8080,8443,9418,27017]) {
    const results = await Promise.all(ports.map(p => scanPort(host, p)));
    const openPorts = results.filter(r => r.open).map(r => r.port);
    return { host, open_ports: openPorts, results };
}

// ─── DNS LOOKUP ───
async function domainLookup(domain) {
    const result = { domain, ip_addresses: [], mx_records: [], txt_records: [], nameservers: [] };
    
    try { result.ip_addresses = await dns.resolve4(domain); } catch {}
    try { result.mx_records = (await dns.resolveMx(domain)).map(m => m.exchange); } catch {}
    try { result.txt_records = await dns.resolveTxt(domain).then(r => r.flat()); } catch {}
    try { result.nameservers = await dns.resolveNs(domain); } catch {}
    
    return result;
}

// ─── IP GEOLOCATION ───
async function lookupIP(ip) {
    try {
        const resp = await httpRequest(`http://ip-api.com/json/${ip}`, { timeout: 10000 });
        if (resp.status === 200) return JSON.parse(resp.body);
    } catch {}
    return { status: 'fail' };
}

// ─── METADATA EXTRACTION ───
async function extractMetadata(filepath) {
    const metadata = {
        filename: path.basename(filepath),
        size_bytes: 0,
        hashes: {}
    };
    
    try {
        const content = fs.readFileSync(filepath);
        metadata.size_bytes = content.length;
        metadata.hashes = {
            md5: md5(content),
            sha1: sha1(content),
            sha256: sha256(content)
        };
        
        // String extraction
        const strings = content.toString('utf-8').match(/[\x20-\x7e]{4,}/g) || [];
        metadata.interesting_strings = strings.filter(s => /http|www|@|password|user|key|token|secret|api/i.test(s)).slice(0, 50);
    } catch (e) {
        metadata.error = e.message;
    }
    
    return metadata;
}

// ─── REPORT GENERATION ───
function generateReport(results, type) {
    const reportDir = path.join(require('os').homedir(), 'raven_reports');
    if (!fs.existsSync(reportDir)) fs.mkdirSync(reportDir, { recursive: true });
    
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const reportPath = path.join(reportDir, `raven_${type}_${timestamp}.md`);
    
    let content = `# Raven OSINT Report\n\n**Type:** ${type}\n**Generated:** ${new Date().toISOString()}\n\n---\n\n`;
    
    if (type === 'username') {
        content += `## Username Search\n\n**Username:** ${results.username}\n**Found:** ${results.found_count}/${results.total_platforms}\n\n`;
        content += '| Platform | Status | URL |\n|---|---|---|\n';
        for (const [platform, data] of Object.entries(results.results)) {
            content += `| ${platform} | ${data.exists ? 'Found' : 'Not Found'} | ${data.url} |\n`;
        }
    } else if (type === 'email') {
        content += `## Email Breach Report\n\n**Email:** ${results.email}\n`;
        content += `**Status:** ${results.breached ? `BREACHED (${results.count} breaches)` : 'No breaches found'}\n`;
    } else if (type === 'ports') {
        content += `## Port Scan Report\n\n**Host:** ${results.host}\n**Open Ports:** ${results.open_ports.join(', ')}\n`;
    }
    
    fs.writeFileSync(reportPath, content);
    return reportPath;
}

// ─── CLI ───
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

function question(prompt) {
    return new Promise(resolve => rl.question(prompt, resolve));
}

async function main() {
    console.log('Raven OSINT Framework — Node.js Version');
    console.log('Available commands: username, email, ports, domain, ip, metadata, hash, exit\n');
    
    while (true) {
        const cmd = (await question('raven> ')).trim().toLowerCase();
        
        if (cmd === 'exit' || cmd === 'quit') break;
        
        if (cmd === 'username') {
            const username = await question('Username: ');
            console.log('Searching...');
            const results = await searchUsername(username);
            console.log(`\nFound ${results.found_count}/${results.total_platforms} platforms:`);
            for (const [platform, data] of Object.entries(results.results)) {
                if (data.exists) console.log(`  [+] ${platform}: ${data.url}`);
            }
        } else if (cmd === 'email') {
            const email = await question('Email: ');
            const result = await checkEmailBreach(email);
            if (result.breached) console.log(`⚠️ BREACHED — ${result.count} breaches`);
            else console.log('✅ No known breaches');
        } else if (cmd === 'ports') {
            const host = await question('Host: ');
            console.log('Scanning...');
            const results = await scanPorts(host);
            console.log(`Open ports: ${results.open_ports.join(', ') || 'none'}`);
        } else if (cmd === 'domain') {
            const domain = await question('Domain: ');
            const results = await domainLookup(domain);
            console.log(JSON.stringify(results, null, 2));
        } else if (cmd === 'ip') {
            const ip = await question('IP: ');
            const results = await lookupIP(ip);
            console.log(JSON.stringify(results, null, 2));
        } else if (cmd === 'metadata') {
            const filepath = await question('File path: ');
            const results = await extractMetadata(filepath);
            console.log(JSON.stringify(results, null, 2));
        } else if (cmd === 'hash') {
            const text = await question('Text: ');
            console.log(`MD5: ${md5(text)}`);
            console.log(`SHA1: ${sha1(text)}`);
            console.log(`SHA256: ${sha256(text)}`);
            console.log(`SHA512: ${sha512(text)}`);
        } else {
            console.log('Unknown command');
        }
    }
    
    rl.close();
}

// Export for module use
module.exports = {
    searchUsername,
    checkEmailBreach,
    scanPorts,
    domainLookup,
    lookupIP,
    extractMetadata,
    generateReport,
    sha1,
    sha256,
    sha512,
    md5
};

// Run CLI if executed directly
if (require.main === module) {
    main().catch(console.error);
}