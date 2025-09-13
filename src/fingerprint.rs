use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

pub async fn fingerprint_software(
    client: &Client,
    subs: &HashSet<String>,
    max_concurrency: usize,
    timeout_secs: u64,
) -> HashMap<String, HashMap<String, String>> {
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

            if let Some(resp) = timeout(Duration::from_secs(timeout_secs), client.get(&url).send())
                .await
                .ok()
                .and_then(|r| r.ok())
            {
                let headers_to_check = vec![
                    "server",
                    "x-powered-by",
                    "x-aspnet-version",
                    "x-request-id",
                    "via",
                    "x-backend-server",
                ];

                for header_name in headers_to_check {
                    if let Some(value) = resp.headers().get(header_name) {
                        if let Ok(value_str) = value.to_str() {
                            fingerprints.insert(header_name.to_string(), value_str.to_string());
                        }
                    }
                }

                if let Some(body_text) = timeout(Duration::from_secs(5), resp.text())
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                {
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
