use rand::seq::SliceRandom;
use reqwest::{header, Client};
use serde::Deserialize;
use std::collections::HashSet;
use std::time::Duration;
use tokio::time::sleep;

use crate::constants::USER_AGENTS;

#[derive(Debug, Deserialize)]
struct CrtShEntry {
    name_value: String,
}

pub async fn crtsh_enum_async(
    client: &Client,
    domain: &str,
    max_retries: usize,
) -> Result<HashSet<String>, Box<dyn std::error::Error>> {
    let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
    let mut retries = 0;
    let mut last_error: Option<Box<dyn std::error::Error>> = None;

    while retries < max_retries {
        let resp = client
            .get(&url)
            .header(
                header::USER_AGENT,
                *USER_AGENTS.choose(&mut rand::thread_rng()).unwrap(),
            )
            .header(header::ACCEPT, "application/json")
            .send()
            .await;

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
                        }
                        Err(e) => {
                            last_error = Some(Box::new(e));
                        }
                    }
                } else if r.status().is_server_error() {
                    last_error = Some(Box::new(std::io::Error::other(format!(
                        "Server error: {}",
                        r.status()
                    ))));
                }
            }
            Err(e) => {
                last_error = Some(Box::new(e));
            }
        }

        retries += 1;
        if retries < max_retries {
            let delay = Duration::from_secs(2_u64.pow(retries as u32));
            println!(
                "[!] Retry {}/{} due to error: {:?}",
                retries, max_retries, last_error
            );
            sleep(delay).await;
        }
    }

    Err(last_error.unwrap_or_else(|| Box::new(std::io::Error::other("Max retries exceeded"))))
}
