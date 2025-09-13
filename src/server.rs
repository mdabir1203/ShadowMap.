use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use shadowmap::{run, Args};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Clone)]
struct Job {
    domain: String,
    status: String,
    output_path: Option<String>,
}

#[derive(Clone)]
struct AppState {
    tokens: HashMap<String, String>, // token -> tenant
    jobs: Arc<Mutex<HashMap<String, HashMap<String, Job>>>>, // tenant -> jobs
}

#[derive(Deserialize)]
struct JobRequest {
    domain: String,
}

#[derive(Serialize)]
struct JobResponse {
    id: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
}

async fn write_json(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
        status,
        body.len(),
        body
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

async fn write_not_found(stream: &mut TcpStream) {
    let _ = stream
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        .await;
}

async fn handle_connection(mut stream: TcpStream, state: Arc<AppState>) {
    let mut buf = Vec::new();
    if stream.read_to_end(&mut buf).await.is_err() {
        return;
    }

    let request = String::from_utf8_lossy(&buf);
    let mut lines = request.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => return,
    };
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    // Extract token
    let mut token = None;
    for line in &mut lines {
        if line.is_empty() {
            break;
        }
        if let Some(value) = line.strip_prefix("Authorization: ") {
            if let Some(t) = value.strip_prefix("Bearer ") {
                token = Some(t.trim().to_string());
            }
        }
    }

    let token = match token {
        Some(t) => t,
        None => {
            let _ = stream
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
    };

    let tenant = match state.tokens.get(&token) {
        Some(t) => t.clone(),
        None => {
            let _ = stream
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n")
                .await;
            return;
        }
    };

    match (method, path) {
        ("POST", "/jobs") => {
            // Body is after headers separated by empty line
            let body = request.split("\r\n\r\n").nth(1).unwrap_or("");
            let req: JobRequest = match serde_json::from_str(body) {
                Ok(b) => b,
                Err(_) => {
                    write_not_found(&mut stream).await;
                    return;
                }
            };
            let id: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(16)
                .map(char::from)
                .collect();
            let job = Job {
                domain: req.domain.clone(),
                status: "queued".into(),
                output_path: None,
            };
            {
                let mut jobs = state.jobs.lock().unwrap();
                jobs.entry(tenant.clone())
                    .or_default()
                    .insert(id.clone(), job);
            }
            let args = Args {
                domain: req.domain,
                concurrency: 50,
                timeout: 10,
                retries: 3,
            };
            let (status, output) = match run(args).await {
                Ok(p) => ("completed".to_string(), Some(p)),
                Err(_) => ("failed".to_string(), None),
            };
            {
                let mut jobs = state.jobs.lock().unwrap();
                if let Some(map) = jobs.get_mut(&tenant) {
                    if let Some(j) = map.get_mut(&id) {
                        j.status = status;
                        j.output_path = output;
                    }
                }
            }
            let body = serde_json::to_string(&JobResponse { id: id.clone() }).unwrap();
            write_json(&mut stream, "200 OK", &body).await;
        }
        ("GET", p) if p.starts_with("/jobs/") => {
            let parts: Vec<&str> = p.split('/').collect();
            if parts.len() == 3 {
                let job_id = parts[2];
                let body = {
                    let jobs = state.jobs.lock().unwrap();
                    jobs.get(&tenant).and_then(|m| m.get(job_id)).map(|job| {
                        serde_json::to_string(&StatusResponse {
                            status: job.status.clone(),
                        })
                        .unwrap()
                    })
                };
                if let Some(body) = body {
                    write_json(&mut stream, "200 OK", &body).await;
                } else {
                    write_not_found(&mut stream).await;
                }
            } else if parts.len() == 4 && parts[3] == "report" {
                let job_id = parts[2];
                let info = {
                    let jobs = state.jobs.lock().unwrap();
                    jobs.get(&tenant).and_then(|m| m.get(job_id)).and_then(|j| {
                        if j.status == "completed" {
                            j.output_path.clone().map(|p| (p, j.domain.clone()))
                        } else {
                            None
                        }
                    })
                };
                if let Some((path, domain)) = info {
                    let file = format!("{}/{}_report.json", path, domain);
                    match tokio::fs::read_to_string(file).await {
                        Ok(contents) => {
                            write_json(&mut stream, "200 OK", &contents).await;
                        }
                        Err(_) => write_not_found(&mut stream).await,
                    }
                } else {
                    write_not_found(&mut stream).await;
                }
            } else {
                write_not_found(&mut stream).await;
            }
        }
        _ => {
            write_not_found(&mut stream).await;
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut tokens = HashMap::new();
    tokens.insert("testtoken".to_string(), "tenant1".to_string());
    let state = Arc::new(AppState {
        tokens,
        jobs: Arc::new(Mutex::new(HashMap::new())),
    });

    let listener = TcpListener::bind(("0.0.0.0", 8080)).await?;
    loop {
        let (socket, _) = listener.accept().await?;
        let state_clone = state.clone();
        handle_connection(socket, state_clone).await;
    }
}
