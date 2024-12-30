use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Replace the sample below with your own migration scripts
        manager
            .drop_table(Table::drop().table(UserGroup::Table).if_exists().to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(Group::Table).if_exists().to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(User::Table).if_exists().to_owned())
            .await?;

        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Ok(())
    }
}

/// Learn more at https://docs.rs/sea-query#iden
#[derive(Iden)]
enum UserGroup {
    Table,
}

#[derive(Iden)]
enum User {
    Table,
}

#[derive(Iden)]
enum Group {
    Table,
}
