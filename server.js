const express = require('express');
const cors = require('cors');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// Algorithm: Levenshtein Distance for Typosquatting
function getLevenshteinDistance(a, b) {
    const matrix = Array.from({ length: a.length + 1 }, () => 
        Array(b.length + 1).fill(0)
    );

    for (let i = 0; i <= a.length; i++) matrix[i][0] = i;
    for (let j = 0; j <= b.length; j++) matrix[0][j] = j;

    for (let i = 1; i <= a.length; i++) {
        for (let j = 1; j <= b.length; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            matrix[i][j] = Math.min(
                matrix[i - 1][j] + 1,
                matrix[i][j - 1] + 1,
                matrix[i - 1][j - 1] + cost
            );
        }
    }
    return matrix[a.length][b.length];
}

// Target brand watchlist for impersonation checks
const TARGET_BRANDS = [
    'google', 'paypal', 'maybank', 'cimb', 'netflix', 
    'microsoft', 'apple', 'facebook', 'instagram', 'binance', 'telegram'
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.work', '.click', '.fit', '.tk', '.ml', '.ga', '.cf', '.gq', '.zip'];
const SUSPICIOUS_KEYWORDS = ['login', 'verify', 'update', 'secure', 'banking', 'account', 'wallet', 'claim', 'free', 'bonus'];

// Core Heuristic Scanner
function analyzeUrl(rawUrl) {
    let formattedUrl = rawUrl.trim();
    if (!/^https?:\/\//i.test(formattedUrl)) {
        formattedUrl = 'http://' + formattedUrl;
    }

    let parsed;
    try {
        parsed = new URL(formattedUrl);
    } catch (e) {
        throw new Error('Invalid URL format.');
    }

    const hostname = parsed.hostname.toLowerCase();
    const pathname = parsed.pathname.toLowerCase();
    const findings = [];
    let riskScore = 0;

    // 1. Check IP address as host
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    if (ipRegex.test(hostname)) {
        riskScore += 45;
        findings.push({ severity: 'High', msg: 'Raw IP address used as hostname instead of a domain.' });
    }

    // 2. Protocol Check
    if (parsed.protocol === 'http:') {
        riskScore += 15;
        findings.push({ severity: 'Medium', msg: 'Unencrypted HTTP protocol detected (No SSL/TLS).' });
    }

    // 3. Suspicious TLD
    const hasSuspiciousTld = SUSPICIOUS_TLDS.some(tld => hostname.endsWith(tld));
    if (hasSuspiciousTld) {
        riskScore += 25;
        findings.push({ severity: 'High', msg: 'High-risk Top-Level Domain (TLD) frequently used in disposable phishing.' });
    }

    // 4. Excessive Subdomains
    const parts = hostname.split('.');
    if (parts.length > 3) {
        riskScore += 20;
        findings.push({ severity: 'Medium', msg: `Multiple subdomains detected (${parts.length} levels). Common obfuscation technique.` });
    }

    // 5. Keyword Injection in Path or Subdomain
    const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => hostname.includes(kw) || pathname.includes(kw));
    if (foundKeywords.length > 0) {
        riskScore += 20;
        findings.push({ severity: 'Medium', msg: `Urgency/Banking keywords detected: [${foundKeywords.join(', ')}]` });
    }

    // 6. Typosquatting & Brand Spoofing Check
    let spoofedBrand = null;
    const domainBody = parts.length >= 2 ? parts[parts.length - 2] : parts[0];

    for (const brand of TARGET_BRANDS) {
        if (domainBody === brand) continue; // Exact legit brand domain

        const distance = getLevenshteinDistance(domainBody, brand);
        // Distance 1 or 2 means slight typo or impersonation (e.g., paypa1, m4ybank)
        if (distance > 0 && distance <= 2 && domainBody.length >= 4) {
            spoofedBrand = brand;
            riskScore += 50;
            findings.push({
                severity: 'Critical',
                msg: `Possible Typosquatting / Impersonation of brand "${brand}" (Similarity distance: ${distance}).`
            });
            break;
        }
    }

    // Cap score at 100
    riskScore = Math.min(riskScore, 100);

    let verdict = 'Safe';
    if (riskScore >= 70) verdict = 'Dangerous';
    else if (riskScore >= 35) verdict = 'Suspicious';

    return {
        url: formattedUrl,
        hostname: hostname,
        riskScore: riskScore,
        verdict: verdict,
        findings: findings
    };
}

// API Endpoint
app.post('/api/scan-url', (req, res) => {
    const { url } = req.body;
    if (!url) {
        return res.status(400).json({ error: 'URL is required.' });
    }

    try {
        const result = analyzeUrl(url);
        return res.json(result);
    } catch (err) {
        return res.status(400).json({ error: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`[+] PhishGuard Scanner active on http://localhost:${PORT}`);
});