use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use std::env;
use std::io::Cursor;
use poseidon_rs::Fr;
use ff_ce::{PrimeField, PrimeFieldRepr};

pub struct Db {
    pub pool: PgPool,
}

impl Db {
    pub async fn new() -> Result<Self, String> {
        dotenvy::dotenv().ok();

        let password =
            env::var("DB_PASSWORD").map_err(|_| "DB_PASSWORD not set".to_string())?;

        let database_url = format!(
            "postgres://postgres:{}@localhost/issuer_db",
            password
        );

        let pool = PgPoolOptions::new()
            .max_connections(5)
            .connect(&database_url)
            .await
            .map_err(|e| format!("DB connection failed: {e}"))?;

        println!("Connected to DB successfully.");

        Self::init_schema(&pool).await?;

        println!("Initializing schema...");

        Ok(Db { pool })
    }

    async fn init_schema(pool: &PgPool) -> Result<(), String> {
        println!("Creating tables if not exist...");

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS claims (
                id BIGINT PRIMARY KEY,
                commitment TEXT NOT NULL
            );
            "#,
        )
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to create claims table: {e}"))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS issuer_states (
                id BIGSERIAL PRIMARY KEY,
                state TEXT NOT NULL,
                claims_root TEXT NOT NULL,
                revocation_root TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
            "#,
        )
        .execute(pool)
        .await
        .map_err(|e| format!("Failed to create issuer_states table: {e}"))?;

        println!("Tables ready.");
        Ok(())
    }
    pub async fn save_claim(
        &self,
        id: u64,
        commitment: &Fr,
    ) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO claims (id, commitment) VALUES ($1, $2)
             ON CONFLICT (id) DO UPDATE SET commitment = EXCLUDED.commitment"
        )
        .bind(id as i64)
        .bind(commitment.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Insert claim failed: {e}"))?;

        Ok(())
    }

    pub async fn load_claims(&self) -> Result<Vec<(u64, Fr)>, String> {
        let rows = sqlx::query("SELECT id, commitment FROM claims")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| format!("Load claims failed: {e}"))?;

        let mut claims = Vec::with_capacity(rows.len());
        for row in rows {
                let id: i64 = row.get("id");
                let commitment: String = row.get("commitment");
            let commitment = parse_fr(&commitment)
                .ok_or_else(|| format!("Invalid commitment in DB for id {id}: {commitment}"))?;
            claims.push((id as u64, commitment));
        }

        Ok(claims)
    }

    pub async fn save_state(
        &self,
        state: &Fr,
        claims_root: &Fr,
        revocation_root: &Fr,
    ) -> Result<(), String> {
        sqlx::query(
            "
            INSERT INTO issuer_states
            (state, claims_root, revocation_root)
            VALUES ($1,$2,$3)
            ",
        )
        .bind(state.to_string())
        .bind(claims_root.to_string())
        .bind(revocation_root.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Insert state failed: {e}"))?;

        Ok(())
    }
}

fn parse_fr(value: &str) -> Option<Fr> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed.strip_prefix("Fr(0x").and_then(|v| v.strip_suffix(")")) {
        return parse_hex_fr(hex);
    }
    if let Some(hex) = trimmed.strip_prefix("0x") {
        return parse_hex_fr(hex);
    }
    Fr::from_str(trimmed)
}

fn parse_hex_fr(hex: &str) -> Option<Fr> {
    let hex_owned;
    let hex = if hex.len() % 2 == 1 {
        hex_owned = format!("0{hex}");
        hex_owned.as_str()
    } else {
        hex
    };
    let bytes = ff_ce::hex::decode(hex).ok()?;
    let mut repr = <Fr as PrimeField>::Repr::default();
    let repr_bytes = repr.as_ref().len() * 8;
    if bytes.len() > repr_bytes {
        return None;
    }
    let mut padded = vec![0u8; repr_bytes];
    padded[repr_bytes - bytes.len()..].copy_from_slice(&bytes);
    repr.read_be(Cursor::new(padded)).ok()?;
    Fr::from_repr(repr).ok()
}
