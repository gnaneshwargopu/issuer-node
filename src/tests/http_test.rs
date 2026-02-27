use reqwest::Client;
use serde_json::json;

#[tokio::test]
async fn test_issue_endpoint() {
    let client = Client::new();

    let payload = json!({
        "id": 1,
        "schema": "100",
        "subject": "200",
        "nonce": "1",
        "flags": "0",
        "values": ["10","20","30","40"]
    });

    let res = client
        .post("http://localhost:3000/issue")
        .json(&payload)
        .send()
        .await
        .unwrap();

    assert!(res.status().is_success());
}