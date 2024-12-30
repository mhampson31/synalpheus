pub use sea_orm_migration::prelude::*;

mod m20230101_000001_create_table;
mod m20241230_153222_remove_unused;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230101_000001_create_table::Migration),
            Box::new(m20241230_153222_remove_unused::Migration),
        ]
    }
}
