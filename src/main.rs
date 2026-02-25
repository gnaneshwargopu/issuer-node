mod hash;
mod merkle;
mod claims;
mod issuer;
mod db;

use poseidon_rs::Fr;
use ff_ce::PrimeField;
use claims::claim::Claim;
use issuer::issuer::Issuer;

fn main() {
    println!("Starting Issuer Node (Spec-Aligned 8-Slot Claim)...");

    let mut issuer = Issuer::new();

    // Index slots
    let schema = Fr::from_str("100").unwrap();
    let subject = Fr::from_str("200").unwrap();
    let rev_nonce = Fr::from_str("999").unwrap();
    let flags = Fr::from_str("0").unwrap();

    // Value slots (4 elements)
    let values = [
        Fr::from_str("1").unwrap(),
        Fr::from_str("2").unwrap(),
        Fr::from_str("3").unwrap(),
        Fr::from_str("4").unwrap(),
    ];

    let claim = Claim::new(
        schema,
        subject,
        rev_nonce,
        flags,
        values,
    );

    let root = issuer.issue_claim(0, claim).unwrap();

    println!("New Claims Root: {:?}", root);
}