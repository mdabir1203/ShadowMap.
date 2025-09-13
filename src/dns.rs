use std::collections::HashSet;
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use trust_dns_resolver::{config::*, TokioAsyncResolver};

use crate::constants::DNS_TIMEOUT;

pub async fn create_secure_resolver(
) -> Result<TokioAsyncResolver, Box<dyn std::error::Error + Send + Sync>> {
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

pub async fn check_dns_live(
    subs: &HashSet<String>,
    resolver: TokioAsyncResolver,
    max_concurrency: usize,
) -> HashSet<String> {
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
                Ok(Ok(lookup)) if lookup.iter().next().is_some() => Some(sub_clone),
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
