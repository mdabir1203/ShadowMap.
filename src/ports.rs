use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::stream::{FuturesUnordered, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::{timeout, Duration};

use crate::constants::COMMON_PORTS;

pub async fn scan_ports(
    subs: &HashSet<String>,
    max_concurrency: usize,
) -> HashMap<String, Vec<u16>> {
    let semaphore = Arc::new(Semaphore::new(max_concurrency));
    let mut result = HashMap::new();
    let mut tasks = FuturesUnordered::new();

    for sub in subs.iter() {
        for &port in COMMON_PORTS.iter() {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let sub_clone = sub.clone();

            tasks.push(tokio::spawn(async move {
                let scan_result = timeout(
                    Duration::from_secs(2),
                    TcpStream::connect((sub_clone.as_str(), port)),
                )
                .await;

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
