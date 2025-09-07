use reqwest::{Client, header};
use serde::Deserialize;
use tokio::time::{sleep, Duration, timeout};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashSet, HashMap};
use std::fs::File;
use std::io::Write;
use regex::Regex;
use idna::domain_to_unicode;
use chrono::Local;
use csv::Writer;
use rand::seq::SliceRandom;
use trust_dns_resolver::{TokioAsyncResolver, config::*};
use lazy_static::lazy_static;
use tokio::net::TcpStream;
use std::sync::Arc;
use tokio::sync::Semaphore;
use std::net::SocketAddr;
use itertools::Itertools;
use clap::Parser;


#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Target domain to perform subdomain enumeration on
    #[arg(short, long, default_value = "example.com")]
    domain: String,
    
    /// Maximum number of concurrent connections
    #[arg(short, long, default_value = "50")]
    concurrency: usize,
    
    /// Request timeout in seconds
    #[arg(short, long, default_value = "10")]
    timeout: u64,
    
    /// Number of retries for failed requests
    #[arg(short, long, default_value = "3")]
    retries: usize,
}

#[derive(Debug, Deserialize)]
struct CrtShEntry { 
    name_value: String,
    not_before: Option<String>,
    not_after: Option<String>,
}

const RETRIES: usize = 3;
const TIMEOUT_SECS: u64 = 5;
const MAX_CONCURRENCY: usize = 35;
const COMMON_PORTS: &[u16] = &[21,22,25,80,443,3306,8080,8443,3389,5432,27017,9200,9300];
const DNS_TIMEOUT: Duration = Duration::from_secs(5);

lazy_static! {
    static ref USER_AGENTS: Vec<&'static str> = vec![
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    ];
    static ref SUBDOMAIN_REGEX: Regex = Regex::new(r"^[a-z0-9][-a-z0-9\.]*[a-z0-9]\.([a-z0-9-]+\.)*[a-z0-9]+$").unwrap();
    static ref IP_REGEX: Regex = Regex::new(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$").unwrap();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = format!("recon_results/{}_{}", args.domain, timestamp);
    std::fs::create_dir_all(&output_dir)?;

    println!("[*] Starting security-enhanced recon for *.{}", args.domain);
    println!("[*] Configuration:");
    println!("    - Domain: {}", args.domain);
    println!("    - Concurrency: {}", args.concurrency);
    println!("    - Timeout: {}s", args.timeout);
    println!("    - Retries: {}", args.retries);
    println!("    - Output: {}", output_dir);

    // Enhanced client with better security settings
    let client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .redirect(reqwest::redirect::Policy::limited(2)) // Limit redirects to prevent loops
        .danger_accept_invalid_certs(false) // Don't accept invalid certs by default
        .pool_idle_timeout(Some(Duration::from_secs(30)))
        .build()?;

    // 1️⃣ CRT.sh Enumeration with enhanced validation
    let crt_subs = crtsh_enum_async(&client, &args.domain, args.retries).await?;
    println!("[+] crt.sh found {} potential subdomains", crt_subs.len());

    // 2️⃣ Enhanced Validation & normalization
    let validated_subs: HashSet<String> = crt_subs.into_iter()
        .filter_map(|s| {
            let s = s.replace("*.", "").replace("www.", "");
            let (decoded, result) = domain_to_unicode(&s);
            if result.is_err() {
                return None;
            }
            let s_lower = decoded.to_lowercase();
            
            // Skip IP addresses and invalid domains
            if IP_REGEX.is_match(&s_lower) || !SUBDOMAIN_REGEX.is_match(&s_lower) {
                return None;
            }
            
            // Ensure it ends with our target domain
            if s_lower.ends_with(&format!(".{}", args.domain)) || s_lower == args.domain {
                Some(s_lower)
            } else {
                None
            }
        }).collect();
    println!("[+] Validated {} subdomains", validated_subs.len());

    // 3️⃣ Enhanced DNS Resolution with custom config
    let resolver = create_secure_resolver().await?;
    let live_subs = check_dns_live(&validated_subs, resolver, args.concurrency).await;
    println!("[+] {} live subdomains detected", live_subs.len());

    // 4️⃣ Rate-limited Port Scanning
    let open_ports_map = scan_ports(&live_subs, args.concurrency).await;
    println!("[+] Port scan complete - found {} subdomains with open ports", open_ports_map.len());

    // 5️⃣ Enhanced HTTP Header & TLS check
    let header_map = check_headers_tls(&client, &live_subs, args.concurrency).await;
    println!("[+] Header/TLS check complete");

    // 6️⃣ Enhanced CORS misconfiguration check
    let cors_map = check_cors(&client, &live_subs, args.concurrency).await;
    println!("[+] CORS check complete - found {} potential issues", cors_map.len());

    // 7️⃣ Enhanced Software fingerprinting
    let software_map = fingerprint_software(&client, &live_subs, args.concurrency).await;
    println!("[+] Software fingerprinting complete");

    // 8️⃣ Enhanced Subdomain takeover detection
    let takeover_map = check_subdomain_takeover(&live_subs).await;
    

    
    println!("[+] Takeover check complete - found {} potential targets", takeover_map.len());

    // 9️⃣ Enhanced Reporting
    write_outputs(
        &live_subs,
        &header_map,
        &open_ports_map,
        &cors_map,
        &software_map,
        &takeover_map,
        &output_dir,
        &args.domain
    )?;

    println!("[*] Recon complete. Outputs in: {}", output_dir);
    Ok(())
}

// Create a secure DNS resolver
async fn create_secure_resolver() -> Result<TokioAsyncResolver, Box<dyn std::error::Error>> {
    let mut config = ResolverConfig::default();
    config.add_name_server(NameServerConfig {
        socket_addr: "8.8.8.8:53".parse()?,
        protocol: trust_dns_resolver::config::Protocol::Udp,
        tls_dns_name: None,
        trust_negative_responses: false,
        bind_addr: None,
    });
    
    let opts = ResolverOpts::default();
    
    Ok(TokioAsyncResolver::tokio(config, opts))
}

// ---------- Enhanced CRT.sh Async ----------
async fn crtsh_enum_async(client: &Client, domain: &str, max_retries: usize) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let mut retries = 0;
    let mut last_error: Option<Box<dyn std::error::Error>> = None;

    while retries < max_retries {
        let resp = client.get(&url)
            .header(header::USER_AGENT, *USER_AGENTS.choose(&mut rand::thread_rng()).unwrap())
            .header(header::ACCEPT, "application/json")
            .send().await;

        match resp {
            Ok(r) => {
                if r.status().is_success() {
                    let entries: Result<Vec<CrtShEntry>, _> = r.json().await;
                    match entries {
                        Ok(entries) => {
                            let mut subs = HashSet::new();
                            for entry in entries {
                                for name in entry.name_value.split('\n') {
                                    let trimmed = name.trim();
                                    if !trimmed.is_empty() && !trimmed.starts_with('*') {
                                        subs.insert(trimmed.to_string());
                                    }
                                }
                            }
                            return Ok(subs);
                        },
                        Err(e) => {
                            last_error = Some(Box::new(e));
                        }
                    }
                } else if r.status().is_server_error() {
                    last_error = Some(Box::new(std::io::Error::new(std::io::ErrorKind::Other, format!("Server error: {}", r.status()))));
                }
            },
            Err(e) => {
                last_error = Some(Box::new(e));
            }
        }
        
        retries += 1;
        if retries < max_retries {
            let delay = Duration::from_secs(2_u64.pow(retries as u32));
            println!("[!] Retry {}/{} due to error: {:?}", retries, max_retries, last_error);
            sleep(delay).await;
        }
    }
    
    Err(last_error.unwrap_or_else(|| Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Max retries exceeded"))))
}

// ---------- Enhanced DNS Live Check ----------
async fn check_dns_live(subs: &HashSet<String>, resolver: TokioAsyncResolver, max_concurrency: usize) -> HashSet<String> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let resolver = resolver.clone();
        let sub_clone = sub.clone();
        
        tasks.push(tokio::spawn(async move {
            let result = timeout(DNS_TIMEOUT, resolver.lookup_ip(sub_clone.clone())).await;
            drop(permit);
            
            match result {
                Ok(Ok(lookup)) if !lookup.iter().next().is_none() => Some(sub_clone),
                _ => None,
            }
        }));
    }

    let mut live = HashSet::new();
    while let Some(res) = tasks.next().await {
        if let Ok(Some(s)) = res {
            live.insert(s);
        }
    }

    live
}

// ---------- Enhanced Port Scan ----------
async fn scan_ports(subs: &HashSet<String>, max_concurrency: usize) -> HashMap<String, Vec<u16>> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut result = HashMap::new();
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        for &port in COMMON_PORTS.iter() {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let sub_clone = sub.clone();
            
            tasks.push(tokio::spawn(async move {
                let addr = format!("{}:{}", sub_clone, port);
                let scan_result = timeout(
                    Duration::from_secs(2), 
                    TcpStream::connect(addr.parse::<SocketAddr>().unwrap())
                ).await;
                
                drop(permit);
                
                match scan_result {
                    Ok(Ok(_)) => Some((sub_clone, port)),
                    _ => None,
                }
            }));
        }
    }

    while let Some(res) = tasks.next().await {
        if let Ok(Some((sub, port))) = res {
            result.entry(sub).or_insert_with(Vec::new).push(port);
        }
    }

    result
}

// ---------- Enhanced Header & TLS Check ----------
async fn check_headers_tls(client: &Client, subs: &HashSet<String>, max_concurrency: usize) -> HashMap<String, (u16, Option<String>)> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut result = HashMap::new();
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let sub_clone = sub.clone();
        
        tasks.push(tokio::spawn(async move {
            let urls = vec![
                format!("https://{}", sub_clone),
                format!("http://{}", sub_clone),
            ];
            
            for url in urls {
                match timeout(Duration::from_secs(TIMEOUT_SECS), client.get(&url).send()).await {
                    Ok(Ok(resp)) => {
                        let status = resp.status().as_u16();
                        let server_header = resp.headers()
                            .get("server")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string());
                        
                        drop(permit);
                        return Some((sub_clone, (status, server_header)));
                    },
                    _ => continue,
                }
            }
            drop(permit);
            None
        }));
    }

    while let Some(res) = tasks.next().await {
        if let Ok(Some((sub, data))) = res {
            result.insert(sub, data);
        }
    }
    result
}

// ---------- Enhanced CORS Misconfiguration ----------
async fn check_cors(client: &Client, subs: &HashSet<String>, max_concurrency: usize) -> HashMap<String, Vec<String>> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency / 2)); // lower concurrency for stability
    let mut result = HashMap::new();
    let mut tasks = FuturesUnordered::new();

    // Test against multiple attacker origins
    let test_origins = vec![
        "https://evil.com",
        "http://evil.com",
        "null",
        "https://attacker.example",
    ];

    for sub in subs.iter() {
        for origin in &test_origins {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let client = client.clone();
            let sub_clone = sub.clone();
            let origin_clone = origin.to_string();

            tasks.push(tokio::spawn(async move {
                let url = format!("https://{}", sub_clone);
                let mut issues = Vec::new();

                // Initial misconfig detection
                if let Ok(resp) = timeout(
                    Duration::from_secs(TIMEOUT_SECS),
                    client.get(&url).header("Origin", origin_clone.clone()).send()
                ).await {
                    if let Ok(resp) = resp {
                        if let Some(ao) = resp.headers().get("access-control-allow-origin") {
                            if let Ok(ao_str) = ao.to_str() {
                                if ao_str == "*" {
                                    issues.push("Wildcard CORS allowed".to_string());
                                } else if ao_str == origin_clone {
                                    issues.push(format!("Reflects origin: {}", origin_clone));
                                }

                                if let Some(acac) = resp.headers().get("access-control-allow-credentials") {
                                    if acac == "true" {
                                        issues.push("Allow-Credentials: true".to_string());
                                    }
                                }
                            }
                        }
                    }
                }

                // If a misconfiguration was flagged, try PoC validation
                if !issues.is_empty() {
                    if let Some(leak) = cors_poc_validate(&client, &sub_clone, &origin_clone).await {
                        issues.push(format!("PoC validated: {}", leak));
                    }
                    Some((sub_clone, issues))
                } else {
                    None
                }
            }));

            drop(permit);
        }
    }

    while let Some(res) = tasks.next().await {
        if let Ok(Some((sub, issues))) = res {
            result.entry(sub).or_insert_with(Vec::new).extend(issues);
        }
    }

    result
}

/// Attempt PoC exploitation of detected CORS misconfigurations
async fn cors_poc_validate(client: &Client, sub: &str, origin: &str) -> Option<String> {
    let url = format!("https://{}", sub);

    // Step 1: Preflight OPTIONS request
    let preflight = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("Origin", origin)
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await;

    if let Ok(resp) = preflight {
        let allow_origin = resp.headers().get("access-control-allow-origin")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let allow_methods = resp.headers().get("access-control-allow-methods")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        if allow_origin == "*" || allow_origin == origin || allow_methods.contains("GET") {
            // Step 2: Malicious GET request
            if let Ok(resp) = client.get(&url).header("Origin", origin).send().await {
                if let Ok(body) = resp.text().await {
                    let lower = body.to_lowercase();
                    let sensitive_keywords = vec![
                        "password", "passwd", "token", "apikey", "secret",
                        "credit", "ssn", "authorization"
                    ];

                    for key in &sensitive_keywords {
                        if lower.contains(key) {
                            let snippet = body.chars().take(200).collect::<String>();
                            return Some(format!("Keyword '{}' found, sample: {}", key, snippet));
                        }
                    }
                }
            }
        }
    }

    None
}

// ---------- Enhanced Software Fingerprinting ----------
async fn fingerprint_software(client: &Client, subs: &HashSet<String>, max_concurrency: usize) -> HashMap<String, HashMap<String, String>> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut result = HashMap::new();
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let client = client.clone();
        let sub_clone = sub.clone();
        
        tasks.push(tokio::spawn(async move {
            let url = format!("https://{}", sub_clone);
            let mut fingerprints = HashMap::new();
            
            if let Ok(resp) = timeout(
                Duration::from_secs(TIMEOUT_SECS), 
                client.get(&url).send()
            ).await {
                if let Ok(resp) = resp {
                    // Check common headers for fingerprinting
                    let headers_to_check = vec![
                        "server", "x-powered-by", "x-aspnet-version", 
                        "x-request-id", "via", "x-backend-server"
                    ];
                    
                    for header_name in headers_to_check {
                        if let Some(value) = resp.headers().get(header_name) {
                            if let Ok(value_str) = value.to_str() {
                                fingerprints.insert(header_name.to_string(), value_str.to_string());
                            }
                        }
                    }
                    
                    // Check for common framework patterns in body
                    if let Ok(body) = timeout(
                        Duration::from_secs(5),
                        resp.text()
                    ).await {
                        if let Ok(body_text) = body {
                            let body_lower = body_text.to_lowercase();
                            let tech_indicators = vec![
                                ("wordpress", "wp-content"),
                                ("drupal", "drupal"),
                                ("joomla", "joomla"),
                                ("react", "react"),
                                ("angular", "angular"),
                                ("vue", "vue.js"),
                                ("laravel", "laravel"),
                            ];
                            
                            for (tech, indicator) in tech_indicators {
                                if body_lower.contains(indicator) {
                                    fingerprints.insert("framework".to_string(), tech.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            
            drop(permit);
            if !fingerprints.is_empty() {
                Some((sub_clone, fingerprints))
            } else {
                None
            }
        }));
    }

    while let Some(res) = tasks.next().await {
        if let Ok(Some((sub, fingerprints))) = res {
            result.insert(sub, fingerprints);
        }
    }
    result
}

// ---------- Enhanced Subdomain Takeover ----------
async fn check_subdomain_takeover(subs: &HashSet<String>) -> HashMap<String, Vec<String>> {
    let mut result = HashMap::new();
    let takeover_patterns = vec![
        ("heroku", "Heroku App"),
        ("s3", "AWS S3"),
        ("azure", "Microsoft Azure"),
        ("cloudfront", "AWS CloudFront"),
        ("github", "GitHub Pages"),
        ("firebase", "Firebase"),
        ("netlify", "Netlify"),
        ("vercel", "Vercel"),
    ];

    for sub in subs.iter() {
        let sub_lower = sub.to_lowercase();
        let mut vulnerabilities = Vec::new();
        
        for (pattern, service) in &takeover_patterns {
            if sub_lower.contains(pattern) {
                vulnerabilities.push(format!("Potential {} takeover", service));
            }
        }
        
        if !vulnerabilities.is_empty() {
            result.insert(sub.clone(), vulnerabilities);
        }
    }
    result
}

// ---------- Enhanced Reporting ----------
fn write_outputs(
    subs: &HashSet<String>,
    header_map: &HashMap<String, (u16, Option<String>)>,
    open_ports_map: &HashMap<String, Vec<u16>>,
    cors_map: &HashMap<String, Vec<String>>,
    software_map: &HashMap<String, HashMap<String, String>>,
    takeover_map: &HashMap<String, Vec<String>>,
    output_dir: &str,
    domain: &str
) -> Result<(), Box<dyn std::error::Error>> {
    use itertools::Itertools;
    
    // TXT - Subdomains
    let txt_file = format!("{}/{}_subdomains.txt", output_dir, domain);
    let mut file = File::create(&txt_file)?;
    for sub in subs.iter().sorted() {
        writeln!(file, "{}", sub)?;
    }

    // JSON - Detailed report
    let json_file = format!("{}/{}_report.json", output_dir, domain);
    let mut json_obj = serde_json::Map::new();
    
    for sub in subs.iter().sorted() {
        let mut entry = serde_json::Map::new();
        
        if let Some((status, server)) = header_map.get(sub) {
            entry.insert("http_status".to_string(), serde_json::json!(status));
            entry.insert("server_header".to_string(), serde_json::json!(server));
        }
        
        entry.insert("open_ports".to_string(), 
            serde_json::json!(open_ports_map.get(sub).cloned().unwrap_or_default()));
        
        entry.insert("cors_issues".to_string(), 
            serde_json::json!(cors_map.get(sub).cloned().unwrap_or_default()));
        
        entry.insert("fingerprints".to_string(), 
            serde_json::json!(software_map.get(sub).cloned().unwrap_or_default()));
        
        entry.insert("takeover_risks".to_string(), 
            serde_json::json!(takeover_map.get(sub).cloned().unwrap_or_default()));
        
        json_obj.insert(sub.clone(), serde_json::Value::Object(entry));
    }
    
    std::fs::write(json_file, serde_json::to_string_pretty(&json_obj)?)?;

    // CSV - Summary report
    let csv_file = format!("{}/{}_report.csv", output_dir, domain);
    let mut wtr = Writer::from_path(&csv_file)?;
    wtr.write_record(&[
        "subdomain", "http_status", "server_header", "open_ports", 
        "cors_issues", "fingerprints", "takeover_risks"
    ])?;
    
    for sub in subs.iter().sorted() {
        let (status, server) = header_map.get(sub).cloned().unwrap_or((0, None));
        let ports = open_ports_map.get(sub).map_or("".to_string(), |v| 
            v.iter().map(|p| p.to_string()).join(","));
        let cors = cors_map.get(sub).map_or("".to_string(), |v| v.join("; "));
        let fingerprints = software_map.get(sub).map_or("".to_string(), |v| 
            serde_json::to_string(v).unwrap_or_default());
        let takeover = takeover_map.get(sub).map_or("".to_string(), |v| v.join("; "));
        
        wtr.write_record(&[
            sub,
            &status.to_string(),
            &server.unwrap_or_default(),
            &ports,
            &cors,
            &fingerprints,
            &takeover,
        ])?;
    }
    wtr.flush()?;

    // Additional security findings summary
    let findings_file = format!("{}/{}_security_findings.txt", output_dir, domain);
    let mut findings = File::create(&findings_file)?;
    
    writeln!(findings, "Security Findings Summary for {}", domain)?;
    writeln!(findings, "=============================================")?;
    writeln!(findings, "Total subdomains found: {}", subs.len())?;
    writeln!(findings, "Subdomains with CORS issues: {}", cors_map.len())?;
    writeln!(findings, "Potential takeover targets: {}", takeover_map.len())?;
    
    Ok(())
}