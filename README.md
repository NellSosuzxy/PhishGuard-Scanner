# PhishGuard — Heuristic URL & Typosquatting Threat Intelligence Engine

![Node.js](https://img.shields.io/badge/Node.js-339933?style=flat-square&logo=nodedotjs&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-000000?style=flat-square&logo=express&logoColor=white)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-38B2AC?style=flat-square&logo=tailwind-css&logoColor=white)
![Algorithm](https://img.shields.io/badge/Algorithm-Levenshtein_Distance-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)

PhishGuard is a sandboxed, zero-execution cybersecurity utility designed to triage suspicious URLs, identify domain typosquatting, and calculate threat indices through algorithmic and structural heuristics.

---

## Key Features

* **Algorithmic Typosquatting Detection:** Utilizes the **Levenshtein Distance Algorithm** (Matrix DP) to identify character substitutions, permutations, and brand impersonations targeting major services (e.g., banking, cloud platforms, social media).
* **Structural URL Dissection:** Evaluates RFC 3986 URL structures, flagging direct raw IPv4 hosts, multi-tier subdomain obfuscation, and suspicious top-level domains (TLDs like `.xyz`, `.top`, `.tk`).
* **Keyword & Urgency Heuristics:** Flags credential phishing vectors embedded within path parameters (e.g., `login`, `verify`, `banking`, `wallet`).
* **SOC-Inspired Terminal Interface:** Built with a dark glassmorphism console layout featuring dynamic circular SVG gauge rendering, live vector logs, and responsive design using Tailwind CSS and Lucide icons.

---

## How It Works

```
[ Target URL Input ]
        │
        ▼ (Local Sanitization & RFC 3986 Parsing)
[ Protocol & Structure Extraction ]
        │
        ├───────────────────────────────┬───────────────────────────────┐
        ▼                               ▼                               ▼
 [ Typosquatting Scan ]        [ Structural Analysis ]         [ Path Inspection ]
  • Levenshtein distance        • Raw IP detection              • Urgency keywords
  • Brand token matching        • Subdomain depth (> 3)         • Unencrypted HTTP
  • Known dictionary pool       • Disposable TLD lists
        │                               │                               │
        └───────────────────────────────┼───────────────────────────────┘
                                        │
                                        ▼
                           [ Heuristic Threat Scoring ]
                                  (0 - 100 Risk Index)
                                        │
                                        ▼
                        [ JSON Output / Web Telemetry ]
```

---

## Tech Stack

* **Backend / Runtime:** Node.js, Express.js, CORS, Node `url` native module
* **Algorithm:** Levenshtein Distance (Dynamic Programming)
* **Frontend:** HTML5, Tailwind CSS, Lucide Icons, JetBrains / Fira Code typography

---

## Project Structure

```text
phishguard-scanner/
├── public/
│   └── index.html       # Terminal threat console UI
├── server.js            # Heuristic inspection engine & REST API
├── package.json         # Dependencies & scripts
├── .gitignore           # Git ignore patterns
└── README.md            # Project documentation
```

---

## Getting Started

### Prerequisites

* [Node.js](https://nodejs.org/) (v16.x or newer)
* `npm` package manager

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/NellSosuzxy/phishguard-scanner.git
   cd phishguard-scanner
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Start the analysis server:
   ```bash
   node server.js
   ```

4. Open the console in your browser:
   ```
   http://localhost:3000
   ```

---

## API Specification

### Analyze Target URL
* **Endpoint:** `POST /api/scan-url`
* **Headers:** `Content-Type: application/json`
* **Request Body:**
  ```json
  {
    "url": "http://mayb4nk2u-secure.xyz/auth"
  }
  ```
* **Sample Response (200 OK):**
  ```json
  {
    "url": "http://mayb4nk2u-secure.xyz/auth",
    "hostname": "mayb4nk2u-secure.xyz",
    "riskScore": 90,
    "verdict": "Dangerous",
    "findings": [
      {
        "severity": "Critical",
        "msg": "Possible Typosquatting / Impersonation of brand \"maybank\" (Similarity distance: 2)."
      },
      {
        "severity": "High",
        "msg": "High-risk Top-Level Domain (TLD) frequently used in disposable phishing."
      },
      {
        "severity": "Medium",
        "msg": "Unencrypted HTTP protocol detected (No SSL/TLS)."
      }
    ]
  }
  ```

---

## License

Distributed under the [MIT License](LICENSE).
