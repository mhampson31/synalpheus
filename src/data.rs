#[cfg(test)]
mod tests {
    use entity::*;
    use sea_orm::{entity::prelude::*, DatabaseBackend, MockDatabase};

    #[tokio::test]
    async fn test_find_application() -> Result<(), DbErr> {
        let app_1 = application::Model {
            id: 1,
            name: "Test App 1".to_owned(),
            slug: "test_app_1".to_owned(),
            launch_url: "localhost/test_app_1".to_owned(),
            icon: None,
            description: Some("This is our first app".to_owned()),
            group: Some("".to_owned()),
        };

        let app_2 = application::Model {
            id: 2,
            name: "Test App 2".to_owned(),
            slug: "test_app_2".to_owned(),
            launch_url: "localhost/test_app_2".to_owned(),
            icon: None,
            description: Some("This is our second app".to_owned()),
            group: Some("Test Group".to_owned()),
        };

        // Create MockDatabase with mock query results
        let db: &DatabaseConnection = &MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([
                // First query result
                vec![app_1.clone()],
                // Second query result
                vec![app_1.clone(), app_2.clone()],
            ])
            .into_connection();

        // Find an app from MockDatabase
        // Return the first query result
        assert_eq!(
            application::Entity::find().one(db).await?,
            Some(app_1.clone())
        );

        // Find all applications
        // Return the second query result
        assert_eq!(
            application::Entity::find().all(db).await?,
            [app_1.clone(), app_2.clone()]
        );

        // Checking transaction log
        /*assert_eq!(
            db.into_transaction_log(),
            [
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "cake"."id", "cake"."name" FROM "cake" LIMIT $1"#,
                    [1u64.into()]
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "cake"."id", "cake"."name" FROM "cake""#,
                    []
                ),
                Transaction::from_sql_and_values(
                    DatabaseBackend::Postgres,
                    r#"SELECT "cake"."id" AS "A_id", "cake"."name" AS "A_name", "fruit"."id" AS "B_id", "fruit"."name" AS "B_name", "fruit"."cake_id" AS "B_cake_id" FROM "cake" LEFT JOIN "fruit" ON "cake"."id" = "fruit"."cake_id""#,
                    []
                ),
            ]
        );*/

        Ok(())
    }
}
