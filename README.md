# CipherScope — Password Strength & Entropy Analyzer

A zero-network, client-side cybersecurity telemetry suite built to analyze password entropy, detect predictable human patterns, and generate cryptographically secure credentials.

## Key Features
- **Real-Time Shannon & Effective Entropy Engine:** Computes bit entropy ($H = L \times \log_2(N)$) and applies heuristic penalties for dictionary tokens, leet-speak substitutions, keyboard walks, repeated characters, and common years.
- **Multi-Scenario Brute-Force Simulator:** Estimates crack times across four hardware tiers (Online Throttled, Standard CPU Argon2/bcrypt, 8x RTX 4090 GPU Rig, and Distributed Supercluster).
- **Web Crypto CSPRNG Studio:** Generates unbiased random strings and Diceware-style passphrases using `window.crypto.getRandomValues()`.
- **100% Client-Side Privacy:** Zero external API calls, cookies, or storage—every calculation executes locally in the browser.

## Tech Stack
- **Frontend:** HTML5, CSS3 (Custom Cyber-Tactile Dark Design System), Vanilla JavaScript (ES6+)
- **Security APIs:** Web Crypto API (`crypto.getRandomValues`)

## Author
**Sayeed Akhter** — BCA Graduate | Cybersecurity & Web Engineering