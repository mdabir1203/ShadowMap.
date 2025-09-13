use std::collections::HashMap;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

pub async fn check_cors(
    client: &Client,
    subs: &std::collections::HashSet<String>,
    max_concurrency: usize,
    timeout_secs: u64,
) -> HashMap<String, Vec<String>> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency / 2));
    let mut result = HashMap::new();
    let mut tasks = FuturesUnordered::new();

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

                if let Some(resp) = timeout(
                    Duration::from_secs(timeout_secs),
                    client
                        .get(&url)
                        .header("Origin", origin_clone.clone())
                        .send(),
                )
                .await
                .ok()
                .and_then(|r| r.ok())
                {
                    if let Some(ao) = resp.headers().get("access-control-allow-origin") {
                        if let Ok(ao_str) = ao.to_str() {
                            if ao_str == "*" {
                                issues.push("Wildcard CORS allowed".to_string());
                            } else if ao_str == origin_clone {
                                issues.push(format!("Reflects origin: {}", origin_clone));
                            }

                            if let Some(acac) =
                                resp.headers().get("access-control-allow-credentials")
                            {
                                if acac == "true" {
                                    issues.push("Allow-Credentials: true".to_string());
                                }
                            }
                        }
                    }
                }

                if !issues.is_empty() {
                    if let Some(leak) = cors_poc_validate(&client, &sub_clone, &origin_clone).await
                    {
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

async fn cors_poc_validate(client: &Client, sub: &str, origin: &str) -> Option<String> {
    let url = format!("https://{}", sub);

    let preflight = client
        .request(reqwest::Method::OPTIONS, &url)
        .header("Origin", origin)
        .header("Access-Control-Request-Method", "GET")
        .send()
        .await;

    if let Ok(resp) = preflight {
        let allow_origin = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let allow_methods = resp
            .headers()
            .get("access-control-allow-methods")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");

        if allow_origin == "*" || allow_origin == origin || allow_methods.contains("GET") {
            if let Ok(resp) = client.get(&url).header("Origin", origin).send().await {
                if let Ok(body) = resp.text().await {
                    let lower = body.to_lowercase();
                    let sensitive_keywords = vec![
                        "password",
                        "passwd",
                        "token",
                        "apikey",
                        "secret",
                        "credit",
                        "ssn",
                        "authorization",
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
