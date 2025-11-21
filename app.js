// Global state
let tokenHistory = [];
let bruteForceRunning = false;
let bruteForceController = null;

const DEFAULT_JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
const DEFAULT_SECRET = 'your-256-bit-secret';

const WEAK_SECRETS = ['secret', 'password', '123456', 'admin', 'test', 'key', 'secret123', 'myapikey', 'jwt_secret', 'token', 'your-256-bit-secret'];

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    initializeTabs();
    initializeDecoderTab();
    initializeEncoderTab();
    initializeBruteForceTab();
    setupAlgorithmWatcher();
});

// Tab Management
function initializeTabs() {
    const tabs = document.querySelectorAll('.tab');
    tabs.forEach(tab => {
        tab.addEventListener('click', () => {
            const tabName = tab.dataset.tab;
            switchTab(tabName);
        });
    });
}

function switchTab(tabName) {
    // Update tab buttons
    document.querySelectorAll('.tab').forEach(tab => {
        tab.classList.remove('active');
        if (tab.dataset.tab === tabName) {
            tab.classList.add('active');
        }
    });

    // Update tab content
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.getElementById(`${tabName}-tab`).classList.add('active');

    // Trigger specific tab actions
    if (tabName === 'security') {
        analyzeJWTSecurity();
    } else if (tabName === 'history') {
        displayHistory();
    }
}

// Decoder Tab
function initializeDecoderTab() {
    const jwtInput = document.getElementById('jwt-input');
    jwtInput.value = DEFAULT_JWT;
    jwtInput.addEventListener('input', debounce(decodeJWT, 300));
    
    document.getElementById('verify-secret').value = DEFAULT_SECRET;
    
    decodeJWT();
}

function decodeJWT() {
    const token = document.getElementById('jwt-input').value.trim();
    
    if (!token) {
        clearDecoded();
        return;
    }

    try {
        const parts = token.split('.');
        
        if (parts.length !== 3) {
            showInvalidToken();
            return;
        }

        // Decode header
        const header = JSON.parse(base64UrlDecode(parts[0]));
        document.getElementById('decoded-header').textContent = syntaxHighlight(JSON.stringify(header, null, 2));

        // Decode payload
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        document.getElementById('decoded-payload').textContent = syntaxHighlight(JSON.stringify(payload, null, 2));

        // Show signature
        document.getElementById('decoded-signature').textContent = parts[2];

        // Show token structure
        displayTokenStructure(parts);

        // Show valid status
        document.getElementById('token-status').innerHTML = `
            <div class="status-indicator status-valid">
                <span>✓</span> Valid JWT Structure
            </div>
        `;

        // Display time-based claims
        displayTimeClaims(payload);

        // Add to history
        addToHistory(token, header.alg || 'Unknown');

        // Update security analyzer if on that tab
        if (document.getElementById('security-tab').classList.contains('active')) {
            analyzeJWTSecurity();
        }

    } catch (error) {
        showInvalidToken();
    }
}

function displayTokenStructure(parts) {
    const structure = document.getElementById('token-structure');
    structure.innerHTML = '';
    structure.className = 'token-structure';
    
    const headerDiv = document.createElement('div');
    headerDiv.className = 'token-part token-header';
    headerDiv.textContent = parts[0].substring(0, 30) + '...';
    headerDiv.title = 'Header';
    
    const payloadDiv = document.createElement('div');
    payloadDiv.className = 'token-part token-payload';
    payloadDiv.textContent = parts[1].substring(0, 30) + '...';
    payloadDiv.title = 'Payload';
    
    const signatureDiv = document.createElement('div');
    signatureDiv.className = 'token-part token-signature';
    signatureDiv.textContent = parts[2].substring(0, 30) + '...';
    signatureDiv.title = 'Signature';
    
    structure.appendChild(headerDiv);
    structure.appendChild(document.createTextNode('.'));
    structure.appendChild(payloadDiv);
    structure.appendChild(document.createTextNode('.'));
    structure.appendChild(signatureDiv);
}

function displayTimeClaims(payload) {
    const container = document.getElementById('time-claims');
    const now = Math.floor(Date.now() / 1000);
    const fiveMinutes = 300;
    
    let html = '';
    
    // Check exp
    if (payload.exp) {
        const remaining = payload.exp - now;
        const status = remaining < 0 ? 'invalid' : (remaining < fiveMinutes ? 'warning' : 'valid');
        const timeStr = remaining < 0 ? `Expired ${formatTimeAgo(Math.abs(remaining))} ago` : `Expires in ${formatTimeAgo(remaining)}`;
        
        html += `
            <div class="claim-item">
                <div class="claim-name">exp (Expiration Time) <span class="status-indicator status-${status}" style="display: inline-flex; padding: 2px 8px; font-size: 11px;">${status === 'valid' ? '✓' : (status === 'warning' ? '⚠' : '✗')}</span></div>
                <div class="claim-value">Unix: ${payload.exp}</div>
                <div class="claim-time">${new Date(payload.exp * 1000).toLocaleString()}</div>
                <div class="claim-time">${timeStr}</div>
            </div>
        `;
    }
    
    // Check iat
    if (payload.iat) {
        const elapsed = now - payload.iat;
        html += `
            <div class="claim-item">
                <div class="claim-name">iat (Issued At)</div>
                <div class="claim-value">Unix: ${payload.iat}</div>
                <div class="claim-time">${new Date(payload.iat * 1000).toLocaleString()}</div>
                <div class="claim-time">Issued ${formatTimeAgo(elapsed)} ago</div>
            </div>
        `;
    }
    
    // Check nbf
    if (payload.nbf) {
        const diff = payload.nbf - now;
        const status = diff > 0 ? 'invalid' : 'valid';
        const timeStr = diff > 0 ? `Valid in ${formatTimeAgo(diff)}` : `Valid since ${formatTimeAgo(Math.abs(diff))} ago`;
        
        html += `
            <div class="claim-item">
                <div class="claim-name">nbf (Not Before) <span class="status-indicator status-${status}" style="display: inline-flex; padding: 2px 8px; font-size: 11px;">${status === 'valid' ? '✓' : '✗'}</span></div>
                <div class="claim-value">Unix: ${payload.nbf}</div>
                <div class="claim-time">${new Date(payload.nbf * 1000).toLocaleString()}</div>
                <div class="claim-time">${timeStr}</div>
            </div>
        `;
    }
    
    if (html === '') {
        html = '<p style="color: var(--text-secondary);">No time-based claims found</p>';
    }
    
    container.innerHTML = html;
}

function formatTimeAgo(seconds) {
    if (seconds < 60) return `${seconds} second${seconds !== 1 ? 's' : ''}`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minute${Math.floor(seconds / 60) !== 1 ? 's' : ''}`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} hour${Math.floor(seconds / 3600) !== 1 ? 's' : ''}`;
    return `${Math.floor(seconds / 86400)} day${Math.floor(seconds / 86400) !== 1 ? 's' : ''}`;
}

function showInvalidToken() {
    document.getElementById('token-status').innerHTML = `
        <div class="status-indicator status-invalid">
            <span>✗</span> Invalid JWT Structure
        </div>
    `;
    clearDecoded();
}

function clearDecoded() {
    document.getElementById('decoded-header').textContent = '';
    document.getElementById('decoded-payload').textContent = '';
    document.getElementById('decoded-signature').textContent = '';
    document.getElementById('token-structure').innerHTML = '';
    document.getElementById('time-claims').innerHTML = '';
}

// Signature Verification
function setupAlgorithmWatcher() {
    const verifyAlg = document.getElementById('verify-algorithm');
    const encodeAlg = document.getElementById('encode-algorithm');
    
    verifyAlg.addEventListener('change', toggleVerificationInputs);
    encodeAlg.addEventListener('change', () => {
        toggleEncodingInputs();
        updateAlgorithmInfo();
    });
    
    toggleVerificationInputs();
    toggleEncodingInputs();
    updateAlgorithmInfo();
}

function toggleVerificationInputs() {
    const algorithm = document.getElementById('verify-algorithm').value;
    const secretGroup = document.getElementById('secret-input-group');
    const publicKeyGroup = document.getElementById('public-key-input-group');
    
    if (algorithm.startsWith('HS')) {
        secretGroup.style.display = 'block';
        publicKeyGroup.style.display = 'none';
    } else {
        secretGroup.style.display = 'none';
        publicKeyGroup.style.display = 'block';
    }
}

function toggleEncodingInputs() {
    const algorithm = document.getElementById('encode-algorithm').value;
    const secretGroup = document.getElementById('encode-secret-group');
    const privateKeyGroup = document.getElementById('encode-private-key-group');
    
    if (algorithm.startsWith('HS')) {
        secretGroup.style.display = 'block';
        privateKeyGroup.style.display = 'none';
    } else {
        secretGroup.style.display = 'none';
        privateKeyGroup.style.display = 'block';
    }
}

function updateAlgorithmInfo() {
    const algorithm = document.getElementById('encode-algorithm').value;
    const infoDiv = document.getElementById('algorithm-info');
    
    const algoInfo = {
        'HS256': 'HMAC with SHA-256 (symmetric, requires shared secret)',
        'HS384': 'HMAC with SHA-384 (symmetric, requires shared secret)',
        'HS512': 'HMAC with SHA-512 (symmetric, requires shared secret)',
        'RS256': 'RSA Signature with SHA-256 (asymmetric, requires private key)',
        'RS384': 'RSA Signature with SHA-384 (asymmetric, requires private key)',
        'RS512': 'RSA Signature with SHA-512 (asymmetric, requires private key)',
        'ES256': 'ECDSA with SHA-256 (asymmetric, requires private key)',
        'ES384': 'ECDSA with SHA-384 (asymmetric, requires private key)',
        'ES512': 'ECDSA with SHA-512 (asymmetric, requires private key)'
    };
    
    infoDiv.textContent = algoInfo[algorithm] || '';
}

async function verifySignature() {
    const token = document.getElementById('jwt-input').value.trim();
    const algorithm = document.getElementById('verify-algorithm').value;
    const resultDiv = document.getElementById('verification-result');
    
    if (!token) {
        resultDiv.innerHTML = '<div class="status-indicator status-invalid">No token to verify</div>';
        return;
    }
    
    try {
        const parts = token.split('.');
        if (parts.length !== 3) {
            throw new Error('Invalid token format');
        }
        
        const header = JSON.parse(base64UrlDecode(parts[0]));
        const headerAlg = header.alg;
        
        if (algorithm.startsWith('HS')) {
            const secret = document.getElementById('verify-secret').value;
            if (!secret) {
                resultDiv.innerHTML = '<div class="status-indicator status-warning">Please enter a secret key</div>';
                return;
            }
            
            const isValid = await verifyHMAC(parts[0] + '.' + parts[1], parts[2], secret, algorithm);
            
            if (isValid) {
                resultDiv.innerHTML = '<div class="status-indicator status-valid">✓ Signature Verified</div>';
                showToast('Signature verified successfully!');
            } else {
                resultDiv.innerHTML = '<div class="status-indicator status-invalid">✗ Signature Invalid</div>';
            }
        } else {
            resultDiv.innerHTML = '<div class="status-indicator status-warning">⚠ RSA/ECDSA verification not fully supported in browser (requires crypto libraries)</div>';
        }
    } catch (error) {
        resultDiv.innerHTML = `<div class="status-indicator status-invalid">✗ Error: ${error.message}</div>`;
    }
}

async function verifyHMAC(data, signature, secret, algorithm) {
    try {
        const hashAlgo = algorithm.replace('HS', 'SHA-');
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
            'raw',
            encoder.encode(secret),
            { name: 'HMAC', hash: hashAlgo },
            false,
            ['sign']
        );
        
        const signatureBytes = await crypto.subtle.sign(
            'HMAC',
            key,
            encoder.encode(data)
        );
        
        const computedSignature = base64UrlEncode(signatureBytes);
        return computedSignature === signature;
    } catch (error) {
        console.error('HMAC verification error:', error);
        return false;
    }
}

// Encoder Tab
function initializeEncoderTab() {
    document.getElementById('header-json').value = JSON.stringify({ alg: 'HS256', typ: 'JWT' }, null, 2);
    document.getElementById('payload-json').value = JSON.stringify({ sub: '1234567890', name: 'John Doe' }, null, 2);
    document.getElementById('encode-secret').value = DEFAULT_SECRET;
}

function updateHeaderAlgorithm() {
    const algorithm = document.getElementById('encode-algorithm').value;
    try {
        const header = JSON.parse(document.getElementById('header-json').value);
        header.alg = algorithm;
        document.getElementById('header-json').value = JSON.stringify(header, null, 2);
    } catch (error) {
        // Invalid JSON, just update the algorithm field
        document.getElementById('header-json').value = JSON.stringify({ alg: algorithm, typ: 'JWT' }, null, 2);
    }
}

function addClaim(claimType) {
    try {
        const payload = JSON.parse(document.getElementById('payload-json').value);
        const now = Math.floor(Date.now() / 1000);
        
        switch (claimType) {
            case 'exp':
                payload.exp = now + 3600; // 1 hour from now
                break;
            case 'iat':
                payload.iat = now;
                break;
            case 'nbf':
                payload.nbf = now;
                break;
            case 'sub':
                payload.sub = 'user-id-123';
                break;
            case 'aud':
                payload.aud = 'your-app';
                break;
            case 'iss':
                payload.iss = 'your-domain.com';
                break;
        }
        
        document.getElementById('payload-json').value = JSON.stringify(payload, null, 2);
        showToast(`Added ${claimType} claim`);
    } catch (error) {
        showToast('Invalid JSON in payload');
    }
}

async function generateJWT() {
    try {
        const header = JSON.parse(document.getElementById('header-json').value);
        const payload = JSON.parse(document.getElementById('payload-json').value);
        const algorithm = document.getElementById('encode-algorithm').value;
        
        const headerEncoded = base64UrlEncode(JSON.stringify(header));
        const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
        const data = headerEncoded + '.' + payloadEncoded;
        
        let signature = '';
        
        if (algorithm.startsWith('HS')) {
            const secret = document.getElementById('encode-secret').value;
            if (!secret) {
                showToast('Please enter a secret key');
                return;
            }
            signature = await signHMAC(data, secret, algorithm);
        } else {
            showToast('RSA/ECDSA signing not fully supported in browser');
            signature = 'signature-placeholder';
        }
        
        const jwt = data + '.' + signature;
        document.getElementById('generated-jwt').value = jwt;
        
        // Show token info
        document.getElementById('token-info').innerHTML = `
            Token Length: ${jwt.length} characters | Size: ${new Blob([jwt]).size} bytes
        `;
        
        showToast('JWT generated successfully!');
    } catch (error) {
        showToast('Error generating JWT: ' + error.message);
    }
}

async function signHMAC(data, secret, algorithm) {
    const hashAlgo = algorithm.replace('HS', 'SHA-');
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
        'raw',
        encoder.encode(secret),
        { name: 'HMAC', hash: hashAlgo },
        false,
        ['sign']
    );
    
    const signatureBytes = await crypto.subtle.sign(
        'HMAC',
        key,
        encoder.encode(data)
    );
    
    return base64UrlEncode(signatureBytes);
}

function loadGeneratedToken() {
    const token = document.getElementById('generated-jwt').value;
    if (token) {
        document.getElementById('jwt-input').value = token;
        switchTab('decode');
        decodeJWT();
        showToast('Token loaded to decoder');
    }
}

function generateSecret() {
    const length = parseInt(document.getElementById('secret-length').value);
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    const base64 = btoa(String.fromCharCode(...bytes));
    
    document.getElementById('generated-secret').innerHTML = `
        <div class="card" style="margin-top: 10px;">
            <h4>Generated Secret (Hex):</h4>
            <div class="json-viewer">
                <button class="copy-btn small" onclick="copyText('${hex}')">Copy</button>
                <pre>${hex}</pre>
            </div>
            <h4 style="margin-top: 15px;">Generated Secret (Base64):</h4>
            <div class="json-viewer">
                <button class="copy-btn small" onclick="copyText('${base64}')">Copy</button>
                <pre>${base64}</pre>
            </div>
        </div>
    `;
    
    showToast('Strong secret generated!');
}

// Security Analyzer
function analyzeJWTSecurity() {
    const token = document.getElementById('jwt-input').value.trim();
    const resultsDiv = document.getElementById('vulnerability-results');
    const recommendationsDiv = document.getElementById('security-recommendations');
    
    if (!token) {
        resultsDiv.innerHTML = '<p style="color: var(--text-secondary);">No token to analyze</p>';
        recommendationsDiv.innerHTML = '';
        return;
    }
    
    try {
        const parts = token.split('.');
        const header = JSON.parse(base64UrlDecode(parts[0]));
        const payload = JSON.parse(base64UrlDecode(parts[1]));
        
        const vulnerabilities = [];
        const recommendations = [];
        
        // Check for none algorithm
        if (header.alg && header.alg.toLowerCase() === 'none') {
            vulnerabilities.push({
                name: 'None Algorithm Attack',
                severity: 'critical',
                description: 'Token uses "alg: none" which allows signature bypass. This is a critical security vulnerability.'
            });
            recommendations.push('Never use "none" algorithm in production. Always require signature verification.');
        }
        
        // Check for weak algorithm
        if (header.alg === 'HS256') {
            vulnerabilities.push({
                name: 'Algorithm Confusion Risk',
                severity: 'high',
                description: 'Using HS256 (symmetric) instead of RS256 (asymmetric) can lead to algorithm confusion attacks.'
            });
            recommendations.push('Consider using RS256 or ES256 for better security in production environments.');
        }
        
        // Check for missing expiration
        if (!payload.exp) {
            vulnerabilities.push({
                name: 'Missing Expiration',
                severity: 'medium',
                description: 'Token lacks exp claim, meaning it never expires and can be replayed indefinitely.'
            });
            recommendations.push('Always include exp claim with a reasonable expiration time (e.g., 1 hour for access tokens).');
        }
        
        // Check for JKU/JWK header injection
        if (header.jku || header.jwk) {
            vulnerabilities.push({
                name: 'JKU/JWK Header Injection Risk',
                severity: 'critical',
                description: 'Token contains jku or jwk parameters which can be exploited to inject malicious keys.'
            });
            recommendations.push('Remove jku/jwk parameters or implement strict validation and whitelisting.');
        }
        
        // Check for missing critical claims
        if (!payload.iss && !payload.aud && !payload.sub) {
            vulnerabilities.push({
                name: 'Missing Critical Claims',
                severity: 'medium',
                description: 'Token lacks important claims like iss, aud, or sub which help prevent token misuse.'
            });
            recommendations.push('Include iss, aud, and sub claims to properly identify token issuer, audience, and subject.');
        }
        
        // Check token expiration
        if (payload.exp) {
            const now = Math.floor(Date.now() / 1000);
            if (payload.exp < now) {
                vulnerabilities.push({
                    name: 'Expired Token',
                    severity: 'high',
                    description: 'Token has expired and should not be accepted.'
                });
            }
        }
        
        // Display results
        if (vulnerabilities.length === 0) {
            resultsDiv.innerHTML = `
                <div class="status-indicator status-valid">
                    ✓ No critical vulnerabilities detected
                </div>
                <p style="margin-top: 15px; color: var(--text-secondary);">However, always ensure you follow security best practices for production use.</p>
            `;
        } else {
            let html = '';
            vulnerabilities.forEach(vuln => {
                html += `
                    <div class="vulnerability-item severity-${vuln.severity}">
                        <div class="vulnerability-title">
                            ${vuln.name}
                            <span class="severity-badge" style="background: var(--${vuln.severity === 'critical' ? 'critical' : (vuln.severity === 'high' ? 'error' : (vuln.severity === 'medium' ? 'warning' : 'accent-primary'))}); color: white;">
                                ${vuln.severity.toUpperCase()}
                            </span>
                        </div>
                        <div style="margin-top: 5px; color: var(--text-secondary);">${vuln.description}</div>
                    </div>
                `;
            });
            resultsDiv.innerHTML = html;
        }
        
        // Display recommendations
        if (recommendations.length > 0) {
            let html = '<ul style="list-style: none; padding: 0;">';
            recommendations.forEach(rec => {
                html += `<li style="padding: 10px; margin-bottom: 10px; background: var(--bg-secondary); border-radius: 8px; border-left: 3px solid var(--accent-primary);">💡 ${rec}</li>`;
            });
            html += '</ul>';
            recommendationsDiv.innerHTML = html;
        } else {
            recommendationsDiv.innerHTML = '<p style="color: var(--text-secondary);">No specific recommendations at this time.</p>';
        }
        
    } catch (error) {
        resultsDiv.innerHTML = '<p style="color: var(--error);">Error analyzing token</p>';
    }
}

// Brute Force Tab
function initializeBruteForceTab() {
    document.getElementById('wordlist').value = WEAK_SECRETS.join('\n');
    document.getElementById('bruteforce-token').value = DEFAULT_JWT;
}

async function startBruteForce() {
    if (bruteForceRunning) {
        showToast('Brute force already running');
        return;
    }
    
    const token = document.getElementById('bruteforce-token').value.trim();
    const wordlist = document.getElementById('wordlist').value.split('\n').filter(s => s.trim());
    
    if (!token) {
        showToast('Please enter a token');
        return;
    }
    
    if (wordlist.length === 0) {
        showToast('Please enter a wordlist');
        return;
    }
    
    bruteForceRunning = true;
    bruteForceController = { stopped: false };
    
    const parts = token.split('.');
    if (parts.length !== 3) {
        showToast('Invalid token format');
        bruteForceRunning = false;
        return;
    }
    
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const algorithm = header.alg;
    
    if (!algorithm.startsWith('HS')) {
        showToast('Brute force only works with HMAC algorithms (HS256/384/512)');
        bruteForceRunning = false;
        return;
    }
    
    const data = parts[0] + '.' + parts[1];
    const targetSignature = parts[2];
    
    const statusDiv = document.getElementById('bruteforce-status');
    const resultDiv = document.getElementById('bruteforce-result');
    const statsDiv = document.getElementById('bruteforce-stats');
    const progressBar = document.getElementById('bruteforce-progress');
    
    statusDiv.innerHTML = '<div class="status-indicator status-warning">🔄 Brute force in progress...</div>';
    resultDiv.innerHTML = '';
    
    const startTime = Date.now();
    let attempts = 0;
    
    for (let i = 0; i < wordlist.length; i++) {
        if (bruteForceController.stopped) {
            statusDiv.innerHTML = '<div class="status-indicator status-invalid">⏹ Brute force stopped</div>';
            bruteForceRunning = false;
            return;
        }
        
        const secret = wordlist[i].trim();
        attempts++;
        
        const progress = ((i + 1) / wordlist.length * 100).toFixed(1);
        progressBar.style.width = progress + '%';
        progressBar.textContent = progress + '%';
        
        const elapsed = (Date.now() - startTime) / 1000;
        const rate = attempts / elapsed;
        statsDiv.innerHTML = `Attempts: ${attempts}/${wordlist.length} | Rate: ${rate.toFixed(0)} attempts/sec | Elapsed: ${elapsed.toFixed(1)}s`;
        
        try {
            const isValid = await verifyHMAC(data, targetSignature, secret, algorithm);
            
            if (isValid) {
                statusDiv.innerHTML = '<div class="status-indicator status-valid">✓ Secret Found!</div>';
                resultDiv.innerHTML = `
                    <div class="card" style="background: rgba(0, 255, 136, 0.1); border-color: var(--success);">
                        <h3 style="color: var(--success);">🎯 Secret Cracked!</h3>
                        <p style="margin-top: 10px;">Secret: <strong>${secret}</strong></p>
                        <p style="margin-top: 5px; color: var(--text-secondary);">Found in ${attempts} attempts (${elapsed.toFixed(2)} seconds)</p>
                    </div>
                `;
                showToast('Secret found: ' + secret);
                bruteForceRunning = false;
                return;
            }
        } catch (error) {
            console.error('Error testing secret:', error);
        }
        
        // Allow UI to update
        if (i % 10 === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
    
    statusDiv.innerHTML = '<div class="status-indicator status-invalid">✗ Secret Not Found</div>';
    resultDiv.innerHTML = `
        <div class="card" style="background: rgba(255, 68, 68, 0.1); border-color: var(--error);">
            <h3 style="color: var(--error);">No Match Found</h3>
            <p style="margin-top: 10px;">Tested ${attempts} secrets in ${((Date.now() - startTime) / 1000).toFixed(2)} seconds</p>
            <p style="margin-top: 5px; color: var(--text-secondary);">The secret is not in the wordlist. Try a larger wordlist or the token uses a strong secret.</p>
        </div>
    `;
    
    bruteForceRunning = false;
}

function stopBruteForce() {
    if (bruteForceRunning && bruteForceController) {
        bruteForceController.stopped = true;
        showToast('Stopping brute force...');
    }
}

// Token History
function addToHistory(token, algorithm) {
    const timestamp = new Date().toLocaleString();
    const preview = token.substring(0, 50) + '...';
    
    tokenHistory.unshift({ token, algorithm, timestamp, preview });
    
    // Keep only last 10
    if (tokenHistory.length > 10) {
        tokenHistory.pop();
    }
}

function displayHistory() {
    const container = document.getElementById('history-list');
    
    if (tokenHistory.length === 0) {
        container.innerHTML = '<p style="color: var(--text-secondary); text-align: center; padding: 40px 0;">No tokens in history yet</p>';
        return;
    }
    
    let html = '';
    tokenHistory.forEach((item, index) => {
        html += `
            <div class="history-item" onclick="loadFromHistory(${index})">
                <div class="history-timestamp">${item.timestamp} | Algorithm: ${item.algorithm}</div>
                <div class="history-preview">${item.preview}</div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

function loadFromHistory(index) {
    const item = tokenHistory[index];
    document.getElementById('jwt-input').value = item.token;
    switchTab('decode');
    decodeJWT();
    showToast('Token loaded from history');
}

function clearHistory() {
    tokenHistory = [];
    displayHistory();
    showToast('History cleared');
}

// Utility Functions
function base64UrlDecode(str) {
    // Add padding
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) {
        str += '=';
    }
    return decodeURIComponent(atob(str).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
}

function base64UrlEncode(input) {
    let str;
    if (typeof input === 'string') {
        str = btoa(unescape(encodeURIComponent(input)));
    } else {
        // ArrayBuffer
        str = btoa(String.fromCharCode(...new Uint8Array(input)));
    }
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function syntaxHighlight(json) {
    return json;
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const text = element.textContent || element.value;
    
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!');
    }).catch(err => {
        showToast('Failed to copy');
    });
}

function copyText(text) {
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied to clipboard!');
    }).catch(err => {
        showToast('Failed to copy');
    });
}

function showToast(message) {
    const existingToast = document.querySelector('.toast');
    if (existingToast) {
        existingToast.remove();
    }
    
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.textContent = message;
    document.body.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 3000);
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}