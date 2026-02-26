use postgres::{Client, NoTls};
use poseidon_rs::Fr;
use ff_ce::PrimeField;
use std::env;

pub struct Db {
    pub client: Client,
}

impl Db {
    pub fn new() -> Self {
        dotenvy::dotenv().ok();

        let password =
            env::var("DB_PASSWORD").expect("DB_PASSWORD not set");

        let conn_str = format!(
            "host=localhost user=postgres password={} dbname=issuer_db",
            password
        );

        let client =
            Client::connect(&conn_str, NoTls)
                .expect("Failed to connect to Postgres");

        Db { client }
    }

    pub fn save_claim(
        &mut self,
        id: u64,
        claim: &crate::claims::claim::Claim,
        commitment: &Fr,
    ) {
        self.client
            .execute(
                "INSERT INTO claims
                 (id,i0,i1,i2,i3,v0,v1,v2,v3,commitment)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                &[
                    &(id as i64),
                    &claim.index[0].to_string(),
                    &claim.index[1].to_string(),
                    &claim.index[2].to_string(),
                    &claim.index[3].to_string(),
                    &claim.value[0].to_string(),
                    &claim.value[1].to_string(),
                    &claim.value[2].to_string(),
                    &claim.value[3].to_string(),
                    &commitment.to_string().replace("Fr(", "").replace(")", ""),
                ],
            )
            .expect("Insert claim failed");
    }

    pub fn load_claims(&mut self) -> Vec<(u64, Fr)> {
        let mut out = Vec::new();

        let rows =
            self.client
                .query("SELECT id, commitment FROM claims", &[])
                .expect("Load claims failed");

        for row in rows {
            let id: i64 = row.get(0);
            let commitment_str: String = row.get(1);

        let cleaned = commitment_str
            .replace("Fr(", "")
            .replace(")", "");

        let commitment =
            Fr::from_str(&cleaned)
                .expect("Invalid commitment format");

            out.push((id as u64, commitment));
        }

        out
    }

    pub fn save_state(
        &mut self,
        state: &Fr,
        claims_root: &Fr,
        revocation_root: &Fr,
    ) {
        self.client
            .execute(
                "INSERT INTO issuer_states
                 (state, claims_root, revocation_root)
                 VALUES ($1,$2,$3)",
                &[
                    &state.to_string().replace("Fr(", "").replace(")", ""),
                    &claims_root.to_string().replace("Fr(", "").replace(")", ""),
                    &revocation_root.to_string().replace("Fr(", "").replace(")", ""),
                ],
            )
            .expect("Insert state failed");
    }
}