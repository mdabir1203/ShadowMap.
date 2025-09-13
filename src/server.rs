use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use serde::{Deserialize, Serialize};
use shadowmap::{run, Args};
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use std::collections::HashMap;
use tokio::fs;
use uuid::Uuid;

struct AppState {
    pool: SqlitePool,
    tokens: HashMap<String, String>,
}

fn extract_tenant(req: &HttpRequest, state: &AppState) -> Option<String> {
    let header = req.headers().get("Authorization")?;
    let token = header.to_str().ok()?;
    let token = token.strip_prefix("Bearer ")?;
    state.tokens.get(token).cloned()
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

async fn submit_job(
    state: web::Data<AppState>,
    req: HttpRequest,
    body: web::Json<JobRequest>,
) -> impl Responder {
    if let Some(tenant) = extract_tenant(&req, &state) {
        let id = Uuid::new_v4().to_string();
        if sqlx::query("INSERT INTO jobs (id, domain, status, tenant_id) VALUES (?,?,?,?)")
            .bind(&id)
            .bind(&body.domain)
            .bind("queued")
            .bind(&tenant)
            .execute(&state.pool)
            .await
            .is_err()
        {
            return HttpResponse::InternalServerError().finish();
        }

        let pool = state.pool.clone();
        let domain = body.domain.clone();
        tokio::spawn(async move {
            let args = Args {
                domain: domain.clone(),
                concurrency: 50,
                timeout: 10,
                retries: 3,
            };
            match run(args).await {
                Ok(path) => {
                    let _ = sqlx::query("UPDATE jobs SET status = ?, output_path = ? WHERE id = ?")
                        .bind("completed")
                        .bind(&path)
                        .bind(&id)
                        .execute(&pool)
                        .await;
                }
                Err(_) => {
                    let _ = sqlx::query("UPDATE jobs SET status = ? WHERE id = ?")
                        .bind("failed")
                        .bind(&id)
                        .execute(&pool)
                        .await;
                }
            }
        });

        HttpResponse::Ok().json(JobResponse { id })
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

async fn job_status(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    if let Some(tenant) = extract_tenant(&req, &state) {
        let id = path.into_inner();
        if let Ok(row) = sqlx::query("SELECT status FROM jobs WHERE id = ? AND tenant_id = ?")
            .bind(&id)
            .bind(&tenant)
            .fetch_optional(&state.pool)
            .await
        {
            if let Some(row) = row {
                let status: String = row.get::<String, _>("status");
                return HttpResponse::Ok().json(StatusResponse { status });
            }
        }
        HttpResponse::NotFound().finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

async fn job_report(
    state: web::Data<AppState>,
    req: HttpRequest,
    path: web::Path<String>,
) -> impl Responder {
    if let Some(tenant) = extract_tenant(&req, &state) {
        let id = path.into_inner();
        if let Ok(row) = sqlx::query("SELECT domain, output_path FROM jobs WHERE id = ? AND tenant_id = ? AND status = 'completed'")
            .bind(&id)
            .bind(&tenant)
            .fetch_optional(&state.pool)
            .await
        {
            if let Some(row) = row {
                let domain: String = row.get::<String, _>("domain");
                let output_path: String = row.get::<String, _>("output_path");
                let file_path = format!("{}/{}_report.json", output_path, domain);
                if let Ok(contents) = fs::read_to_string(&file_path).await {
                    return HttpResponse::Ok()
                        .content_type("application/json")
                        .body(contents);
                }
            }
        }
        HttpResponse::NotFound().finish()
    } else {
        HttpResponse::Unauthorized().finish()
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:jobs.db")
        .await
        .expect("Failed to connect to DB");

    sqlx::query("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, domain TEXT NOT NULL, status TEXT NOT NULL, output_path TEXT, tenant_id TEXT NOT NULL)")
        .execute(&pool)
        .await
        .expect("migration");

    let mut tokens = HashMap::new();
    tokens.insert("testtoken".to_string(), "tenant1".to_string());

    let state = web::Data::new(AppState { pool, tokens });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/jobs", web::post().to(submit_job))
            .route("/jobs/{id}", web::get().to(job_status))
            .route("/jobs/{id}/report", web::get().to(job_report))
    })
    .bind(("0.0.0.0", 8080))?
    .run()
    .await
}
