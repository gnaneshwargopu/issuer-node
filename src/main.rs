mod hash;
mod merkle;
mod claims;
mod issuer;
mod db;

use axum::{
    routing::{get, post},
    Router,
    Json,
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use poseidon_rs::Fr;
use ff_ce::PrimeField;

use crate::claims::claim::Claim;
use crate::issuer::issuer::Issuer;

#[derive(Deserialize)]
struct IssueRequest {
    id: u64,
    schema: String,
    subject: String,
    nonce: String,
    flags: String,
    values: [String; 4],
}

#[derive(Serialize)]
struct IssueResponse {
    state: String,
}

#[derive(Serialize)]
struct StateResponse {
    state: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    println!("Starting Issuer HTTP Node...");

    let issuer = match Issuer::new().await {
        Ok(issuer) => Arc::new(RwLock::new(issuer)),
        Err(e) => {
            eprintln!("Failed to initialize issuer: {e}");
            return;
        }
    };

    let app = Router::new()
        .route("/issue", post(issue_claim))
        .route("/state", get(get_state))
        .with_state(issuer);

    let listener = match tokio::net::TcpListener::bind("0.0.0.0:3000").await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("Failed to bind listener: {e}");
            return;
        }
    };

    println!("Server running on http://localhost:3000");

    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("Server error: {e}");
    }
}

async fn issue_claim(
    axum::extract::State(issuer): axum::extract::State<Arc<RwLock<Issuer>>>,
    Json(payload): Json<IssueRequest>,
) -> Result<Json<IssueResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut issuer = issuer.write().await;

    let schema = parse_field(&payload.schema, "schema")?;
    let subject = parse_field(&payload.subject, "subject")?;
    let nonce = parse_field(&payload.nonce, "nonce")?;
    let flags = parse_field(&payload.flags, "flags")?;

    let values = [
        parse_field(&payload.values[0], "values[0]")?,
        parse_field(&payload.values[1], "values[1]")?,
        parse_field(&payload.values[2], "values[2]")?,
        parse_field(&payload.values[3], "values[3]")?,
    ];

    let claim = Claim::new(schema, subject, nonce, flags, values);

    let state = issuer.issue_claim(payload.id, claim).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e,
            }),
        )
    })?;

    Ok(Json(IssueResponse {
        state: state.to_string(),
    }))
}

async fn get_state(
    axum::extract::State(issuer): axum::extract::State<Arc<RwLock<Issuer>>>,
) -> Result<Json<StateResponse>, (StatusCode, Json<ErrorResponse>)> {
    let issuer = issuer.read().await;

    let state = issuer.compute_state().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: e,
            }),
        )
    })?;

    Ok(Json(StateResponse {
        state: state.to_string(),
    }))
}

fn parse_field(
    value: &str,
    name: &str,
) -> Result<Fr, (StatusCode, Json<ErrorResponse>)> {
    Fr::from_str(value).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("invalid field `{name}`: {value}"),
            }),
        )
    })
}
