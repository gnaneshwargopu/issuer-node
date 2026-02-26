mod hash;
mod merkle;
mod claims;
mod issuer;
mod db;

use dotenvy;
use poseidon_rs::Fr;
use ff_ce::PrimeField;

use crate::claims::claim::Claim;
use crate::issuer::issuer::Issuer;

fn main() {
    dotenvy::dotenv().ok();

    println!("Starting Issuer Node (Spec-Aligned 8-Slot Claim)...");

    let mut issuer = Issuer::new();

    let schema = Fr::from_str("100").unwrap();
    let subject = Fr::from_str("200").unwrap();
    let nonce = Fr::from_str("1").unwrap();
    let flags = Fr::from_str("0").unwrap();

    let values = [
        Fr::from_str("10").unwrap(),
        Fr::from_str("20").unwrap(),
        Fr::from_str("30").unwrap(),
        Fr::from_str("40").unwrap(),
    ];

    let claim = Claim::new(schema, subject, nonce, flags, values);

    let state = issuer.issue_claim(0, claim).unwrap();

    println!("New Issuer State: {:?}", state);
}