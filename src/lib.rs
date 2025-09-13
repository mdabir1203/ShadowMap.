pub mod args;
mod cloud;
mod constants;
mod cors;
mod dns;
mod enumeration;
mod fingerprint;
mod headers;
mod ports;
mod reporting;
mod takeover;

pub use args::Args;

use chrono::Local;
use idna::domain_to_unicode;
use reqwest::{redirect::Policy, Client};
use std::collections::HashSet;
use tokio::time::Duration;

use cloud::cloud_saas_recon;
use constants::{IP_REGEX, SUBDOMAIN_REGEX};
use cors::check_cors;
use dns::{check_dns_live, create_secure_resolver};
use enumeration::crtsh_enum_async;
use fingerprint::fingerprint_software;
use headers::check_headers_tls;
use ports::scan_ports;
use reporting::{write_outputs, ReconMaps};
use std::path::Path;
use takeover::check_subdomain_takeover;

pub async fn run(args: Args) -> Result<String, Box<dyn std::error::Error>> {

    let timestamp = Local::now().format("%Y%m%d_%H%M%S").to_string();
    let output_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("recon_results")
        .join(format!("{}_{}", args.domain, timestamp));
    std::fs::create_dir_all(&output_dir)?;
    let output_dir = output_dir.to_string_lossy().to_string();

    println!("[*] Starting security-enhanced recon for *.{}", args.domain);
    println!("[*] Configuration:");
    println!("    - Domain: {}", args.domain);
    println!("    - Concurrency: {}", args.concurrency);
    println!("    - Timeout: {}s", args.timeout);
    println!("    - Retries: {}", args.retries);
    println!("    - Output: {}", output_dir);

    let client = Client::builder()
        .timeout(Duration::from_secs(args.timeout))
        .redirect(Policy::limited(2))
        .danger_accept_invalid_certs(false)
        .pool_idle_timeout(Some(Duration::from_secs(30)))
        .build()?;

    let crt_subs = crtsh_enum_async(&client, &args.domain, args.retries).await?;
    println!("[+] crt.sh found {} potential subdomains", crt_subs.len());

    let validated_subs: HashSet<String> = crt_subs
        .into_iter()
        .filter_map(|s| {
            let s = s.replace("*.", "").replace("www.", "");
            let (decoded, result) = domain_to_unicode(&s);
            if result.is_err() {
                return None;
            }
            let s_lower = decoded.to_lowercase();

            if IP_REGEX.is_match(&s_lower) || !SUBDOMAIN_REGEX.is_match(&s_lower) {
                return None;
            }

            if s_lower.ends_with(&format!(".{}", args.domain)) || s_lower == args.domain {
                Some(s_lower)
            } else {
                None
            }
        })
        .collect();
    println!("[+] Validated {} subdomains", validated_subs.len());

    let resolver = create_secure_resolver().await?;
    let live_subs = check_dns_live(&validated_subs, resolver, args.concurrency).await;
    println!("[+] {} live subdomains detected", live_subs.len());

    let open_ports_map = scan_ports(&live_subs, args.concurrency).await;
    println!(
        "[+] Port scan complete - found {} subdomains with open ports",
        open_ports_map.len()
    );

    let header_map = check_headers_tls(&client, &live_subs, args.concurrency, args.timeout).await;
    println!("[+] Header/TLS check complete");

    let cors_map = check_cors(&client, &live_subs, args.concurrency, args.timeout).await;
    println!(
        "[+] CORS check complete - found {} potential issues",
        cors_map.len()
    );

    let software_map =
        fingerprint_software(&client, &live_subs, args.concurrency, args.timeout).await;
    println!("[+] Software fingerprinting complete");

    let resolver_for_cloud = create_secure_resolver().await?;
    let cloud_saas_map = cloud_saas_recon(&live_subs, resolver_for_cloud, args.concurrency).await;
    println!(
        "[+] Cloud/SaaS reconnaissance complete - found {} subdomains with SaaS patterns or predictions",
        cloud_saas_map.len()
    );

    let takeover_map = check_subdomain_takeover(&live_subs).await;
    println!(
        "[+] Takeover check complete - found {} potential targets (including cloud)",
        takeover_map.len()
    );

    write_outputs(
        &live_subs,
        ReconMaps {
            header_map: &header_map,
            open_ports_map: &open_ports_map,
            cors_map: &cors_map,
            software_map: &software_map,
            takeover_map: &takeover_map,
            cloud_saas_map: &cloud_saas_map,
        },
        &output_dir,
        &args.domain,
    )?;

    println!("[*] Recon complete. Outputs in: {}", output_dir);
    Ok(output_dir)
}