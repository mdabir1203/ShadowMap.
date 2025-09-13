use std::collections::HashMap;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use trust_dns_resolver::TokioAsyncResolver;

use crate::constants::{CLOUD_SAAS_PATTERNS, DNS_TIMEOUT};

pub async fn cloud_saas_recon(
    subs: &std::collections::HashSet<String>,
    resolver: TokioAsyncResolver,
    max_concurrency: usize,
) -> HashMap<String, Vec<String>> {
    let resolver = Arc::new(resolver);
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        let sub_clone = sub.clone();
        let resolver_clone = Arc::clone(&resolver);
        let semaphore_clone = Arc::clone(&semaphore);

        tasks.push(tokio::spawn(async move {
            let _permit = semaphore_clone
                .acquire()
                .await
                .expect("Semaphore unexpectedly closed");

            let mut findings: Vec<String> = Vec::new();

            for (provider, pattern) in CLOUD_SAAS_PATTERNS.iter() {
                if pattern.is_match(&sub_clone) {
                    findings.push(format!("Matched provider pattern: {}", provider));
                }
            }

            let predicted_candidates = vec![
                format!("api.{}", sub_clone),
                format!("dev.{}", sub_clone),
                format!("staging.{}", sub_clone),
                format!("{}.s3.amazonaws.com", sub_clone),
                format!("{}.blob.core.windows.net", sub_clone),
                format!("{}.storage.googleapis.com", sub_clone),
            ];

            for cand in predicted_candidates {
                match timeout(DNS_TIMEOUT, resolver_clone.lookup_ip(cand.clone())).await {
                    Ok(Ok(lookup)) if lookup.iter().next().is_some() => {
                        findings.push(format!("Predicted exists: {}", cand));
                    }
                    _ => {}
                }
            }

            if !findings.is_empty() {
                Some((sub_clone, findings))
            } else {
                None
            }
        }));
    }

    let mut results = HashMap::new();
    while let Some(res) = tasks.next().await {
        if let Ok(Some((sub_clone, findings))) = res {
            results.insert(sub_clone, findings);
        }
    }

    results
}
