use std::collections::HashMap;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

pub async fn check_headers_tls(
    client: &Client,
    subs: &std::collections::HashSet<String>,
    max_concurrency: usize,
    timeout_secs: u64,
) -> HashMap<String, (u16, Option<String>)> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut result = HashMap::new();
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        let client = client.clone();
        let sub_clone = sub.clone();
        let semaphore_clone = semaphore.clone();

        tasks.push(tokio::spawn(async move {
            let permit = match semaphore_clone.acquire_owned().await {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("[!] Failed to acquire semaphore for {}: {}", sub_clone, e);
                    return None;
                }
            };

            let urls = vec![
                format!("https://{}", sub_clone),
                format!("http://{}", sub_clone),
            ];

            let mut final_result = None;

            for url in urls {
                match timeout(Duration::from_secs(timeout_secs), client.get(&url).send()).await {
                    Ok(Ok(resp)) => {
                        let status = resp.status().as_u16();
                        let server_header = resp
                            .headers()
                            .get("server")
                            .and_then(|h| h.to_str().ok())
                            .map(|s| s.to_string());

                        final_result = Some((sub_clone.clone(), (status, server_header)));
                        break;
                    }
                    Ok(Err(e)) => {
                        eprintln!("[!] HTTP request failed for {}: {}", url, e);
                        continue;
                    }
                    Err(_) => {
                        eprintln!("[!] Timeout for {}", url);
                        continue;
                    }
                }
            }

            drop(permit);

            final_result
        }));
    }

    while let Some(res) = tasks.next().await {
        match res {
            Ok(Some((sub, data))) => {
                result.insert(sub, data);
            }
            Ok(None) => {}
            Err(e) => {
                if e.is_panic() {
                    eprintln!("[!] Task panicked: {:?}", e);
                } else {
                    eprintln!("[!] Task failed: {:?}", e);
                }
            }
        }
    }

    result
}
