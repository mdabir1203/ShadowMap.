# 🌑 ShadowMap.
<img width="1024" height="1536" alt="20250909_2018_ShadowMap Logo Design_simple_compose_01k4qgw7v3e6ttp28pvckddh9y-min" src="https://github.com/user-attachments/assets/95d39e5e-d51c-4eb4-9053-2db1e1042410" />

⚡ **Hacker-grade reconnaissance at global scale.**  
ShadowMap is a Rust-powered open-source framework for **subdomain enumeration, vulnerability detection, and attack surface mapping**.  

---

## 🚀 Features  

- 🔍 **Subdomain Discovery** via CRT.sh & multiple sources  
- 🌍 **Global Recon** with IDN normalization & wildcard handling  
- ⚡ **Lightning Fast** async Rust engine with concurrency controls  
- 🛰 **Active Recon Modules**  
  - DNS resolution  
  - Web header & TLS analysis  
  - CORS misconfiguration detection  
  - Open ports scanning (common services + banners)  
  - Software fingerprinting (frameworks, servers, CDNs)  
  - Subdomain takeover detection (AWS S3, Azure, CloudFront, GitHub Pages, etc.)  
- 📊 **Export Formats** → CSV, JSON, TXT (ready for pipelines or reporting)  
- 🛡 **False Positive Reduction** → heuristic checks + fallback validation

## 🔄 Workflow

  <img width="406" height="1376" alt="Unbenannt-2025-09-13-0737" src="https://github.com/user-attachments/assets/365ccf19-2529-45e1-b330-db3ab8dd7031" />

---

## 🛠 Installation  

### Prerequisites  
- Rust (>=1.70)  
- Cargo package manager  

### Build
```bash
git clone https://github.com/YOUR-ORG/ShadowMap.git
cd ShadowMap
cargo build --release
Run
./target/release/shadowmap -d volkswagen.de -o results.csv
```

### Lint

```bash
cargo clippy -- -D warnings
```

🎯 Usage Examples
Enumerate & Analyze Subdomains
```bash
shadowmap -d example.com -o results.csv
```

Run with Custom Concurrency
```bash
shadowmap -d example.com -c 50 -o results.json
```
Export to JSON for Integration

```bash
shadowmap -d target.com --json > report.json
```

📂 Output Example

```csv
subdomain,http_status,server_header,open_ports,cors_issues,fingerprints,takeover_risks
api.example.com,200,nginx,"80,443","Wildcard CORS allowed","{server: nginx, framework: react}","None"
cdn.example.com,0,,,"","",Potential AWS S3 takeover
```

🤖 Roadmap
 Passive + Active DNS integrations (SecurityTrails, Shodan, etc.)

 Advanced port fingerprinting (Nmap integration)

 Plugin system for custom scans

 Cloud asset exposure detection (GCP Buckets, Azure Blobs, etc.)

 Continuous recon mode

💀 Disclaimer
This tool is for educational and authorized security testing only.
Do not use ShadowMap against systems you don’t own or have explicit permission to test.

🌟 Contributing
Pull requests are welcome! Please open an issue to discuss improvements, new modules, or bug fixes.

🧭 Philosophy
ShadowMap is built on the idea that attackers don’t wait.
To defend, researchers need tools that are:

Fast ⚡
Global 🌍
Reliable 🛡

Open-source 🤝
