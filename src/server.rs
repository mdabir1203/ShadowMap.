use rand::{distributions::Alphanumeric, Rng};
use serde::{Deserialize, Serialize};
use shadowmap::{run, Args};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
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

struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

async fn read_request<R: AsyncRead + Unpin>(stream: &mut R) -> Option<Request> {
    let mut buf = Vec::new();
    loop {
        let mut temp = [0u8; 1024];
        let n = stream.read(&mut temp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&temp[..n]);
        if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let header_end = pos + 4;
            let header_slice = &buf[..header_end];
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut req = httparse::Request::new(&mut headers);
            if req.parse(header_slice).ok()? != httparse::Status::Complete(header_end) {
                return None;
            }
            let content_length = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("Content-Length"))
                .and_then(|h| std::str::from_utf8(h.value).ok()?.parse::<usize>().ok())
                .unwrap_or(0);
            let method = req.method.unwrap_or("").to_string();
            let path = req.path.unwrap_or("").to_string();
            let headers_map: HashMap<_, _> = req
                .headers
                .iter()
                .map(|h| {
                    (
                        h.name.to_string(),
                        String::from_utf8_lossy(h.value).to_string(),
                    )
                })
                .collect();
            let mut body = buf[header_end..].to_vec();
            while body.len() < content_length {
                let mut temp = vec![0; content_length - body.len()];
                let n = stream.read(&mut temp).await.ok()?;
                if n == 0 {
                    return None;
                }
                body.extend_from_slice(&temp[..n]);
            }
            return Some(Request {
                method,
                path,
                headers: headers_map,
                body: String::from_utf8_lossy(&body).to_string(),
            });
        }
    }
}

async fn handle_connection(mut stream: TcpStream, state: Arc<AppState>) {
    let request = match read_request(&mut stream).await {
        Some(r) => r,
        None => return,
    };

    // Extract token
    let token = request
        .headers
        .get("Authorization")
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string());

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

    match (request.method.as_str(), request.path.as_str()) {
        ("POST", "/jobs") => {
            let req: JobRequest = match serde_json::from_str(&request.body) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn parses_request() {
        let raw = b"POST /jobs HTTP/1.1\r\nContent-Length: 18\r\nAuthorization: Bearer t\r\n\r\n{\"domain\":\"a.com\"}";
        let mut cursor = BufReader::new(Cursor::new(raw.as_ref()));
        let req = read_request(&mut cursor).await.expect("parse");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/jobs");
        assert_eq!(req.headers.get("Authorization").unwrap(), "Bearer t");
        assert_eq!(req.body, "{\"domain\":\"a.com\"}");
    }
}
