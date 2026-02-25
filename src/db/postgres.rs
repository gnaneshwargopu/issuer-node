use postgres::{Client, NoTls};
use poseidon_rs::Fr;
use ff_ce::PrimeField;
use std::env;
pub struct Db {
    pub client: Client,
}

impl Db {

    pub fn new() -> Self {
        let password = env::var("DB_PASSWORD")
            .expect("DB_PASSWORD environment variable not set");

        let conn_str = format!(
            "host=localhost user=postgres password={} dbname=issuer_db",
            password
        );

        let client = Client::connect(&conn_str, NoTls)
            .expect("Failed to connect to Postgres");

        Db { client }
    }
    pub fn save_claim(
        &mut self,
        id: u64,
        claim: &crate::claims::claim::Claim,
        commitment: &Fr,
    ) {
        self.client.execute(
            "INSERT INTO claims
            (id, i0, i1, i2, i3, v0, v1, v2, v3, commitment)
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
        ).expect("Failed to insert claim");
    }
    pub fn load_claims(&mut self) -> Vec<(u64, Fr)> {
        let mut result = Vec::new();

        for row in self.client.query("SELECT id, commitment FROM claims", &[]).unwrap() {
            let id: i64 = row.get(0);
            let commitment_str: String = row.get(1);

             let cleaned = commitment_str
                .replace("Fr(", "")
                .replace(")", "");

            let commitment = Fr::from_str(&cleaned).unwrap();

            result.push((id as u64, commitment));
        }

        result
    }

    pub fn save_root(&mut self, claims_root: &Fr, revocation_root: &Fr) {
        self.client.execute(
            "INSERT INTO roots (claims_root, revocation_root)
             VALUES ($1, $2)",
            &[&claims_root.to_string(), &revocation_root.to_string()],
        ).unwrap();
    }
}