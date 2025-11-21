# JWT Debugger Pro

Advanced, client-side JSON Web Token debugger and security analyzer for decoding, verifying, building, and stress-testing JWTs directly in the browser. [web:1][web:16]

## Overview

JWT Debugger Pro is a single-page web application that lets you inspect JWT headers and claims, verify signatures, and experiment with different signing algorithms and claim sets. [web:5][web:17]  
All operations (decode, encode, sign, verify, and analysis) are performed entirely in the browser using the Web Crypto API and Base64URL processing, so no tokens are sent to any backend. [web:5][web:21]

## Features

### Decode and verify

- Paste any JWT and see it split into header, payload, and signature with clear visual separation. [web:1][web:100]  
- Pretty-printed JSON views for header and payload with basic validation and error feedback when the structure is invalid. [web:1][web:16]  
- Time-based claim inspection for `exp`, `iat`, and `nbf`, shown as both Unix timestamps and human-readable datetimes, with status indicators such as valid, expired, or not yet valid. [web:75][web:85]  
- Signature verification for common algorithms (HS256/384/512, RS256/384/512, ES256/384/512) using a shared secret or PEM-formatted public key. [web:22][web:24]  

### Encode and sign

- Interactive header editor with default `{ "alg": "HS256", "typ": "JWT" }` and algorithm dropdown that keeps header and algorithm selection in sync. [web:16][web:10]  
- Payload editor with quick-add buttons for common claims like `exp`, `iat`, `nbf`, `sub`, `iss`, and `aud`. [web:75][web:104]  
- Support for symmetric HMAC-based algorithms and asymmetric RSA or ECDSA signatures via text areas for keys. [web:22][web:24]  
- On-demand JWT generation showing the final compact token plus metadata like length or size. [web:16][web:10]  

### Security analyzer

- Detection of tokens using the `none` algorithm, flagging them as a critical vulnerability because they bypass signature verification. [web:3][web:32]  
- Heuristics for weak HMAC secrets based on short length and common dictionary values that are susceptible to brute-force attacks. [web:23][web:28]  
- Warnings about algorithm confusion patterns where an RSA public key might be misused as an HMAC secret if server-side validation is flawed. [web:3][web:32]  
- Checks for missing or weak claims (such as absence of `exp` or `iss`) and presence of risky header parameters like `jku` or `jwk` that can enable key injection. [web:3][web:32]  

### Brute-force and secret tooling (educational)

- Dictionary-based weak-secret tester that tries a supplied wordlist against HS* tokens to demonstrate how quickly poor secrets can be recovered. [web:23][web:33]  
- Live progress display with attempts, duration, and approximate attempts per second to show the impact of secret entropy on attack cost. [web:23][web:28]  
- Strong secret generator that produces random secrets of configurable length for use as HMAC keys or API secrets. [web:23][web:63]  
- Prominent educational and ethical-use warnings clarifying that these capabilities are intended for testing systems you own or are authorized to assess. [web:32][web:35]  

### Token history and documentation

- In-memory history of recent tokens (for example the last ten) that you can quickly reload into the decoder for iterative testing. [web:47][web:96]  
- Embedded documentation tab explaining JWT structure, standard claims, common signing algorithms, and typical attack vectors. [web:16][web:88]  

## JWT basics (for users of the tool)

A JWT is a compact token composed of three Base64URL-encoded parts separated by dots: header, payload, and signature. [web:1][web:100]  
The header usually declares the token type (`typ`) and signing algorithm (`alg`) such as HS256 or RS256. [web:1][web:16]  
The payload contains claims like subject, issuer, audience, and timestamps, which are readable by anyone and should not contain secrets unless encrypted. [web:16][web:10]  
The signature is computed over the encoded header and payload using a secret or private key and is what protects the token from tampering when verified correctly. [web:10][web:32]  

## Tech stack

- Static single-page application written in modern JavaScript, HTML, and CSS with no external runtime dependencies. [web:47][web:96]  
- Web Crypto API for HMAC, RSA, and ECDSA signature operations in supported browsers. [web:21][web:89]  
- Custom Base64URL encode and decode utilities that follow the JWT specification for safe URL transport and signature correctness. [web:16][web:74]  
- Responsive layout using CSS Grid and Flexbox with a dark, security-focused theme suitable for desktop and mobile. [web:46][web:98]  

## Getting started (local usage)

1. Clone or download the repository into a local directory on your machine. [web:52][web:101]  
2. Open the `index.html` file directly in a modern browser, or serve the folder with a simple static file server if you prefer. [web:98][web:101]  
3. Paste an existing JWT into the decode panel or build a new one in the encode panel to start exploring. [web:16][web:5]  

For a more realistic setup, running a small local HTTP server (for example with Python or Node) avoids issues with some browsers’ local file restrictions. [web:98][web:101]  

## Deploying to GitHub Pages

This project is designed to be hosted as a static site from a Git repository using GitHub Pages. [web:52][web:98]  

Typical workflow:

1. Create a new public repository and add the project files (including `index.html`) to the root of the repository. [web:52][web:65]  
2. Commit and push the files to
