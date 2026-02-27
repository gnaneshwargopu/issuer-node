use issuer_node::db::postgres::Db;

#[tokio::test]
async fn test_db_connects() {
    let db = Db::new().await.unwrap();
    assert!(db.load_claims().await.is_ok());
}