#[cfg(test)]
mod tests {
    use sea_orm::{entity::prelude::*, DatabaseBackend, MockDatabase};

    #[tokio::test]
    async fn test_find_cake() -> Result<(), DbErr> {
        // Create MockDatabase with mock query results
        let db = MockDatabase::new(DatabaseBackend::Postgres);
        assert_eq!(1, 2);
        Ok(())
    }
}
